// dotnet new console -lang F#
// dotnet add package FSharp.Data
//
// IOCFlow — pipeline for normalization, deduplication, and enrichment of IOC.

module OsintPipeline

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Text
open System.Text.RegularExpressions
open System.Collections.Generic
open FSharp.Data

type IocKind =
    | IPv4
    | IPv6
    | Domain
    | Url
    | Md5
    | Sha1
    | Sha256

module Kinds =
    let reMd5 = Regex(@"^[a-f0-9]{32}$", RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)
    let reSha1 = Regex(@"^[a-f0-9]{40}$", RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)
    let reSha256 = Regex(@"^[a-f0-9]{64}$", RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)
    let reIpv4 = Regex(@"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$",
                       RegexOptions.CultureInvariant)

    // ASCII DNS labels. IDN can be supplied in punycode form.
    let reDomain =
        Regex(@"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
              RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)

    let validIpv4 (s: string) =
        if String.IsNullOrWhiteSpace s then false
        else
            let m = reIpv4.Match(s.Trim())
            if not m.Success then false
            else
                [1..4]
                |> List.forall (fun i ->
                    let mutable n = 0
                    Int32.TryParse(m.Groups.[i].Value, &n) && n >= 0 && n <= 255)

    /// Canonical dotted-quad form (strips leading zeros).
    let canonicalIpv4 (s: string) : string option =
        if String.IsNullOrWhiteSpace s then None
        else
            let v = s.Trim()
            let m = reIpv4.Match(v)
            if not m.Success then None
            else
                let parts =
                    [1..4]
                    |> List.map (fun i ->
                        let mutable n = -1
                        if Int32.TryParse(m.Groups.[i].Value, &n) && n >= 0 && n <= 255 then Some n
                        else None)

                match parts with
                | [Some a; Some b; Some c; Some d] ->
                    Some (sprintf "%d.%d.%d.%d" a b c d)
                | _ -> None

    let isIpv4 (s: string) = validIpv4 s

    // IPv4-mapped addresses (::ffff:1.2.3.4) are treated as IPv6,
    // because IPAddress.TryParse returns IPv6 for them.
    let isIpv6 (s: string) =
        if String.IsNullOrWhiteSpace s then false
        else
            let core = s.Trim()
            let candidate =
                if core.StartsWith("[") && core.EndsWith("]") then
                    core.Substring(1, core.Length - 2)
                else core

            match IPAddress.TryParse(candidate) with
            | true, ip -> ip.AddressFamily = AddressFamily.InterNetworkV6
            | _ -> false

    let canonicalIpv6 (s: string) =
        let core =
            let x = s.Trim()
            if x.StartsWith("[") && x.EndsWith("]") then
                x.Substring(1, x.Length - 2)
            else x

        match IPAddress.TryParse(core) with
        | true, ip when ip.AddressFamily = AddressFamily.InterNetworkV6 ->
            Some (ip.ToString().ToLowerInvariant())
        | _ -> None

module UrlUtil =

    let tryUri (raw: string) =
        match Uri.TryCreate(raw, UriKind.Absolute) with
        | true, uri -> Some uri
        | _ -> None

    /// Host without IPv6 brackets, lowercased. Suitable for enrichment lookups.
    let private safeHost (uri: Uri) =
        // DnsSafeHost strips IPv6 brackets; Trim is a defensive belt-and-braces.
        uri.DnsSafeHost.Trim([|'['; ']'|]).ToLowerInvariant()

    let tryHost (u: string) : string option =
        match tryUri u with
        | Some uri when uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
                      || uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
                      || uri.Scheme.Equals("ftp", StringComparison.OrdinalIgnoreCase) ->
            Some (safeHost uri)
        | _ -> None

    let canonical (raw: string) : string option =
        if String.IsNullOrWhiteSpace raw then None
        else
            match tryUri (raw.Trim()) with
            | None -> None
            | Some uri ->
                let scheme = uri.Scheme.ToLowerInvariant()
                match scheme with
                | "http" | "https" | "ftp" ->
                    let host = safeHost uri
                    let host =
                        // Re-add brackets for IPv6 in the URL form.
                        if host.Contains ":" then "[" + host + "]" else host

                    let port =
                        match scheme, uri.Port with
                        | "http", 80
                        | "https", 443
                        | "ftp", 21 -> ""
                        | _, p when p > 0 -> sprintf ":%d" p
                        | _ -> ""

                    let path =
                        if String.IsNullOrEmpty uri.AbsolutePath then "/" else uri.AbsolutePath

                    let query =
                        if String.IsNullOrEmpty uri.Query then "" else uri.Query

                    let fragment =
                        if String.IsNullOrEmpty uri.Fragment then "" else uri.Fragment

                    // Intentionally preserve path/query/fragment case and encoding.
                    Some (sprintf "%s://%s%s%s%s%s" scheme host port path query fragment)
                | _ -> None

type RawIoc = {
    Value   : string
    Source  : string
    Kind    : IocKind option
    Tags    : string list
    SeenAt  : DateTime
}

type Ioc = {
    Value   : string
    Kind    : IocKind
    Sources : string list
    Tags    : string list
    SeenAt  : DateTime
}

type Enrichment = {
    GeoCountry : string option
    GeoCity    : string option
    Asn        : string option
    AsnOrg     : string option
    ReverseDns : string option
    Whois      : string option
}

type ReportRow = {
    Ioc             : Ioc
    Enrichment      : Enrichment
    IsWhitelisted   : bool
    WhitelistReasons: string list
}

module Normalize =

    let private defang (s: string) =
        let x =
            Regex.Replace(
                s,
                @"\[\.\]|\(\.\)|\{\.\}|\[dot\]",
                ".",
                RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)

        let x =
            Regex.Replace(
                x,
                @"\[:\]",
                ":",
                RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)

        // Only rewrite "hxxp"/"hxxps" when it is actually acting as a scheme,
        // i.e. followed by "://". This prevents rewriting the token when it
        // appears glued to a preceding word character (e.g. "myhxxp") or as
        // part of an unrelated label (e.g. "hxxp.example.com", ".../hxxp").
        // IgnoreCase makes an explicit (?:x|X) alternation unnecessary.
        Regex.Replace(
            x,
            @"\bhxxp(s?)(?=://)",
            "http$1",
            RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant)

    let guessKind (s: string) : IocKind option =
        if String.IsNullOrWhiteSpace s then None
        else
            let v = s.Trim()
            let lower = v.ToLowerInvariant()

            match lower with
            // Explicit, unambiguous type names.
            | "ipv4" -> Some IPv4
            | "ipv6" -> Some IPv6
            | "domain" -> Some Domain
            | "url" | "uri" -> Some Url
            | "md5" -> Some Md5
            | "sha1" | "sha-1" -> Some Sha1
            | "sha256" | "sha-256" -> Some Sha256
            // Ambiguous aliases ("ip", "hash") fall through to value-based detection.
            | _ ->
                if Kinds.reSha256.IsMatch v then Some Sha256
                elif Kinds.reSha1.IsMatch v then Some Sha1
                elif Kinds.reMd5.IsMatch v then Some Md5
                elif Kinds.isIpv4 v then Some IPv4
                elif Kinds.isIpv6 v then Some IPv6
                elif lower.StartsWith("http://") ||
                     lower.StartsWith("https://") ||
                     lower.StartsWith("ftp://") then Some Url
                // Trim trailing dot before domain check.
                elif Kinds.reDomain.IsMatch (v.TrimEnd('.')) then Some Domain
                else None

    let private canonicalDomain (v: string) =
        let value = v.Trim().TrimEnd('.').ToLowerInvariant()

        if value.Contains("/") || value.Contains("?") || value.Contains("#") then
            match UrlUtil.canonical value with
            | Some u -> Some (u, Url)
            | None -> None
        elif Kinds.reDomain.IsMatch value then
            Some (value, Domain)
        else
            None

    let canonical (raw: string) (kind: IocKind option) : (string * IocKind) option =
        if String.IsNullOrWhiteSpace raw then None
        else
            let v = defang (raw.Trim())
            let selectedKind = kind |> Option.orElseWith (fun () -> guessKind v)

            match selectedKind with
            | Some IPv4 ->
                match Kinds.canonicalIpv4 v with
                | Some canon -> Some (canon, IPv4)
                | None -> None

            | Some IPv6 ->
                match Kinds.canonicalIpv6 v with
                | Some value -> Some (value, IPv6)
                | None -> None

            | Some Domain ->
                canonicalDomain v

            | Some Url ->
                match UrlUtil.canonical v with
                | Some u -> Some (u, Url)
                | None -> None

            | Some Md5 when Kinds.reMd5.IsMatch v ->
                Some (v.ToLowerInvariant(), Md5)

            | Some Sha1 when Kinds.reSha1.IsMatch v ->
                Some (v.ToLowerInvariant(), Sha1)

            | Some Sha256 when Kinds.reSha256.IsMatch v ->
                Some (v.ToLowerInvariant(), Sha256)

            | Some Md5 | Some Sha1 | Some Sha256 ->
                None

            | None -> None

    let normalize (r: RawIoc) : Ioc option =
        canonical r.Value r.Kind
        |> Option.map (fun (value, kind) ->
            { Value = value
              Kind = kind
              Sources =
                  if String.IsNullOrWhiteSpace r.Source then []
                  else [r.Source.Trim()]
              Tags =
                  r.Tags
                  |> List.map (fun t -> t.Trim().ToLowerInvariant())
                  |> List.filter (fun t -> t.Length > 0)
                  |> List.distinct
                  |> List.sort
              SeenAt = r.SeenAt })

type ParseError = {
    Source : string
    Path   : string
    Message: string
}

module Parsing =

    let private tryJsonString (v: JsonValue) : string option =
        try Some (v.AsString())
        with _ -> None

    let private parseTags (t: string) : string list =
        if String.IsNullOrWhiteSpace t then []
        else
            t.Split([|';'; ','|], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun s -> s.Trim().ToLowerInvariant())
            |> Array.filter (fun s -> s.Length > 0)
            |> Array.distinct
            |> Array.toList

    let parseCsv (source: string) (path: string) : Result<RawIoc list, ParseError> =
        try
            let rows =
                CsvFile.Load(path).Rows
                |> Seq.choose (fun row ->
                    match row.TryGetColumn "indicator" with
                    | Some value when not (String.IsNullOrWhiteSpace value) ->
                        let kind =
                            match row.TryGetColumn "type" with
                            | Some t when not (String.IsNullOrWhiteSpace t) ->
                                Normalize.guessKind t
                            | _ -> None

                        let tags =
                            match row.TryGetColumn "tags" with
                            | Some t -> parseTags t
                            | None -> []

                        Some {
                            Value = value.Trim()
                            Source = source
                            Kind = kind
                            Tags = tags
                            SeenAt = DateTime.UtcNow
                        }
                    | _ -> None)
                |> Seq.toList

            Ok rows
        with ex ->
            Error {
                Source = source
                Path = path
                Message = ex.Message
            }

    let parseJson (source: string) (path: string) : Result<RawIoc list, ParseError> =
        try
            let doc = JsonValue.Load(path)

            let rows =
                doc.AsArray()
                |> Array.choose (fun item ->
                    let valueOpt =
                        match item.TryGetProperty "value" with
                        | Some v -> tryJsonString v |> Option.map (fun s -> s.Trim())
                        | None -> None

                    match valueOpt with
                    | None -> None
                    | Some value when String.IsNullOrWhiteSpace value -> None
                    | Some value ->
                        let kind =
                            match item.TryGetProperty "type" with
                            | Some t ->
                                tryJsonString t |> Option.bind Normalize.guessKind
                            | None -> None

                        let tags =
                            match item.TryGetProperty "tags" with
                            | Some t ->
                                try
                                    t.AsArray()
                                    |> Array.choose (fun v ->
                                        tryJsonString v
                                        |> Option.map (fun s -> s.Trim().ToLowerInvariant()))
                                    |> Array.distinct
                                    |> Array.toList
                                with _ -> []
                            | None -> []

                        Some {
                            Value = value
                            Source = source
                            Kind = kind
                            Tags = tags
                            SeenAt = DateTime.UtcNow
                        })
                |> Array.toList

            Ok rows
        with ex ->
            Error {
                Source = source
                Path = path
                Message = ex.Message
            }

    let parseStixLite (source: string) (path: string) : Result<RawIoc list, ParseError> =
        // Path segment may itself contain quoted parts, e.g. file:hashes.'SHA-256'.
        let pairRe =
            Regex(
                @"([A-Za-z0-9_:\-\.']+)\s*=\s*'([^']+)'",
                RegexOptions.CultureInvariant)

        let kindOfPath (objectPath: string) : IocKind option =
            let p = objectPath.ToLowerInvariant()

            if p.Contains("ipv4-addr") then Some IPv4
            elif p.Contains("ipv6-addr") then Some IPv6
            elif p.Contains("domain-name") then Some Domain
            elif p.Contains("url") then Some Url
            elif p.Contains("sha-256") || p.Contains("sha256") then Some Sha256
            elif p.Contains("sha-1") || p.Contains("sha1") then Some Sha1
            elif p.Contains("md5") then Some Md5
            else None

        try
            let doc = JsonValue.Load(path)

            match doc.TryGetProperty "objects" with
            | None ->
                Error {
                    Source = source
                    Path = path
                    Message = "Missing 'objects' property."
                }

            | Some objects ->
                let objectsArr =
                    try objects.AsArray()
                    with _ ->
                        raise (FormatException("'objects' is not an array."))

                let rows =
                    objectsArr
                    |> Array.choose (fun obj ->
                        match obj.TryGetProperty "pattern" with
                        | None -> None
                        | Some p ->
                            match tryJsonString p with
                            | None -> None
                            | Some pattern ->
                                let found =
                                    pairRe.Matches(pattern)
                                    |> Seq.cast<Match>
                                    |> Seq.tryPick (fun m ->
                                        match kindOfPath m.Groups.[1].Value with
                                        | Some kind -> Some (m.Groups.[2].Value, kind)
                                        | None -> None)

                                match found with
                                | None -> None
                                | Some (value, kind) ->
                                    let tags =
                                        match obj.TryGetProperty "labels" with
                                        | Some labels ->
                                            try
                                                labels.AsArray()
                                                |> Array.choose (fun v ->
                                                    tryJsonString v
                                                    |> Option.map (fun s -> s.Trim().ToLowerInvariant()))
                                                |> Array.distinct
                                                |> Array.toList
                                            with _ -> []
                                        | None -> []

                                    Some {
                                        Value = value
                                        Source = source
                                        Kind = Some kind
                                        Tags = tags
                                        SeenAt = DateTime.UtcNow
                                    })
                    |> Array.toList

                Ok rows
        with ex ->
            Error {
                Source = source
                Path = path
                Message = ex.Message
            }

module Dedup =

    let private key (i: Ioc) = (i.Kind, i.Value)

    let private merge (a: Ioc) (b: Ioc) =
        { a with
            Sources = (a.Sources @ b.Sources) |> List.distinct |> List.sort
            Tags = (a.Tags @ b.Tags) |> List.distinct |> List.sort
            SeenAt = max a.SeenAt b.SeenAt }

    let deduplicate (iocs: Ioc seq) : Ioc list =
        iocs
        |> Seq.fold
            (fun (acc: Dictionary<_, Ioc>) ioc ->
                let k = key ioc
                match acc.TryGetValue k with
                | true, existing -> acc.[k] <- merge existing ioc
                | false, _ -> acc.[k] <- ioc
                acc)
            (Dictionary())
        |> fun d ->
            d.Values
            |> Seq.sortBy (fun i -> i.Kind, i.Value)
            |> Seq.toList

type IGeoIp =
    abstract Lookup : string -> (string * string) option

type IAsn =
    abstract Lookup : string -> (string * string) option

type IReverseDns =
    abstract Lookup : string -> string option

type IWhois =
    abstract Lookup : string -> string option

module Enrich =

    let private emptyEnrichment = {
        GeoCountry = None
        GeoCity = None
        Asn = None
        AsnOrg = None
        ReverseDns = None
        Whois = None
    }

    let private enrichIp (geo: IGeoIp) (asn: IAsn) (rdns: IReverseDns) (ip: string) =
        let g = geo.Lookup ip
        let a = asn.Lookup ip

        { emptyEnrichment with
            GeoCountry = g |> Option.map fst
            GeoCity = g |> Option.map snd
            Asn = a |> Option.map fst
            AsnOrg = a |> Option.map snd
            ReverseDns = rdns.Lookup ip }

    let private enrichDomain (whois: IWhois) (domain: string) =
        { emptyEnrichment with
            Whois = whois.Lookup domain }

    let enrich
        (geo: IGeoIp)
        (asn: IAsn)
        (rdns: IReverseDns)
        (whois: IWhois)
        (ioc: Ioc) : Enrichment =

        match ioc.Kind with
        | IPv4 | IPv6 ->
            enrichIp geo asn rdns ioc.Value

        | Domain ->
            enrichDomain whois ioc.Value

        | Url ->
            match UrlUtil.tryHost ioc.Value with
            | Some host ->
                match Normalize.guessKind host with
                | Some IPv4 | Some IPv6 -> enrichIp geo asn rdns host
                | Some Domain -> enrichDomain whois host
                | _ -> emptyEnrichment
            | None -> emptyEnrichment

        | Md5 | Sha1 | Sha256 ->
            emptyEnrichment

type WhitelistRule =
    | ExactValue of IocKind * string
    | DomainSuffix of string
    | CidrRange of string * int
    | TagMatch of string

module Whitelist =

    let private ipToUInt32 (ip: string) =
        let parts = ip.Split('.') |> Array.map UInt32.Parse
        (parts.[0] <<< 24) |||
        (parts.[1] <<< 16) |||
        (parts.[2] <<< 8) |||
        parts.[3]

    let private inIpv4Cidr (ip: string) (network: string) (prefix: int) =
        if prefix < 0 || prefix > 32 then false
        elif not (Kinds.isIpv4 ip && Kinds.isIpv4 network) then false
        else
            let ipN = ipToUInt32 ip
            let netN = ipToUInt32 network
            let mask =
                if prefix = 0 then 0u
                else UInt32.MaxValue <<< (32 - prefix)

            (ipN &&& mask) = (netN &&& mask)

    let private ipv6Bytes (s: string) =
        match IPAddress.TryParse s with
        | true, ip when ip.AddressFamily = AddressFamily.InterNetworkV6 ->
            Some (ip.GetAddressBytes())
        | _ -> None

    let private inIpv6Cidr (ip: string) (network: string) (prefix: int) =
        if prefix < 0 || prefix > 128 then false
        else
            match ipv6Bytes ip, ipv6Bytes network with
            | Some ipBytes, Some netBytes ->
                let fullBytes = prefix / 8
                let remainingBits = prefix % 8

                let fullEqual =
                    [0 .. fullBytes - 1]
                    |> List.forall (fun i -> ipBytes.[i] = netBytes.[i])

                if not fullEqual then false
                elif remainingBits = 0 then true
                else
                    let mask = byte (0xFF <<< (8 - remainingBits))
                    (ipBytes.[fullBytes] &&& mask) =
                    (netBytes.[fullBytes] &&& mask)
            | _ -> false

    let private domainMatches (host: string) (suffix: string) =
        let h = host.Trim().TrimEnd('.').ToLowerInvariant()
        let s = suffix.Trim().Trim('.').ToLowerInvariant()

        h = s || h.EndsWith("." + s, StringComparison.Ordinal)

    let private hostKind (host: string) =
        Normalize.guessKind host

    let private checkHostRules (rules: WhitelistRule list) (host: string) =
        let normalizedHost =
            match hostKind host with
            | Some IPv6 ->
                Kinds.canonicalIpv6 host |> Option.defaultValue host
            | _ ->
                host.Trim().TrimEnd('.').ToLowerInvariant()

        rules
        |> List.choose (fun rule ->
            match rule with
            | DomainSuffix suffix
                when hostKind normalizedHost = Some Domain &&
                     domainMatches normalizedHost suffix ->
                Some (sprintf "domain-suffix %s" suffix)

            | CidrRange (net, prefix)
                when hostKind normalizedHost = Some IPv4 &&
                     inIpv4Cidr normalizedHost net prefix ->
                Some (sprintf "cidr %s/%d" net prefix)

            | CidrRange (net, prefix)
                when hostKind normalizedHost = Some IPv6 &&
                     inIpv6Cidr normalizedHost net prefix ->
                Some (sprintf "cidr %s/%d" net prefix)

            | _ -> None)

    let private canonicalRuleValue (kind: IocKind) (value: string) : string option =
        match kind with
        | Domain ->
            let v = value.Trim().TrimEnd('.').ToLowerInvariant()
            if Kinds.reDomain.IsMatch v then Some v else None

        | Md5 ->
            let v = value.Trim().ToLowerInvariant()
            if Kinds.reMd5.IsMatch v then Some v else None

        | Sha1 ->
            let v = value.Trim().ToLowerInvariant()
            if Kinds.reSha1.IsMatch v then Some v else None

        | Sha256 ->
            let v = value.Trim().ToLowerInvariant()
            if Kinds.reSha256.IsMatch v then Some v else None

        | IPv4 ->
            Kinds.canonicalIpv4 value

        | IPv6 ->
            Kinds.canonicalIpv6 value

        | Url ->
            UrlUtil.canonical value

    let check (rules: WhitelistRule list) (ioc: Ioc) : string list =
        let directMatches =
            rules
            |> List.choose (fun rule ->
                match rule with
                | ExactValue (kind, value) when kind = ioc.Kind ->
                    match canonicalRuleValue kind value with
                    | Some canonical when canonical = ioc.Value ->
                        Some (sprintf "exact match %A:%s" kind value)
                    | _ -> None

                | TagMatch tag ->
                    let normalized = tag.Trim().ToLowerInvariant()
                    if normalized.Length > 0 && List.contains normalized ioc.Tags then
                        Some (sprintf "tag %s" tag)
                    else None

                | _ -> None)

        let hostMatches =
            match ioc.Kind with
            | Domain ->
                checkHostRules rules ioc.Value

            | Url ->
                match UrlUtil.tryHost ioc.Value with
                | Some host -> checkHostRules rules host
                | None -> []

            | IPv4 | IPv6 ->
                checkHostRules rules ioc.Value

            | Md5 | Sha1 | Sha256 ->
                []

        directMatches @ hostMatches
        |> List.distinct

module Report =

    let private fmtOpt = function
        | Some v -> v
        | None -> "-"

    let private kindName = function
        | IPv4 -> "IPv4"
        | IPv6 -> "IPv6"
        | Domain -> "Domain"
        | Url -> "Url"
        | Md5 -> "Md5"
        | Sha1 -> "Sha1"
        | Sha256 -> "Sha256"

    let private optStr = function
        | Some s -> JsonValue.String s
        | None -> JsonValue.Null

    let toRows
        (enrich: Ioc -> Enrichment)
        (rules: WhitelistRule list)
        (iocs: Ioc list) : ReportRow list =

        iocs
        |> List.map (fun ioc ->
            let enrichment = enrich ioc
            let reasons = Whitelist.check rules ioc

            { Ioc = ioc
              Enrichment = enrichment
              IsWhitelisted = not reasons.IsEmpty
              WhitelistReasons = reasons })

    let renderText (rows: ReportRow list) : string =
        let sb = StringBuilder()

        sb.AppendLine("=== IOC Enrichment Report ===") |> ignore
        sb.AppendLine(
            sprintf "Total: %d | Whitelisted: %d"
                rows.Length
                (rows |> List.filter (fun r -> r.IsWhitelisted) |> List.length))
        |> ignore
        sb.AppendLine() |> ignore

        for row in rows do
            let flag = if row.IsWhitelisted then " [WHITELISTED]" else ""

            sb.AppendLine(
                sprintf "%s %s%s"
                    (kindName row.Ioc.Kind)
                    row.Ioc.Value
                    flag)
            |> ignore

            sb.AppendLine(sprintf "  sources : %s" (String.concat ", " row.Ioc.Sources)) |> ignore

            if not row.Ioc.Tags.IsEmpty then
                sb.AppendLine(sprintf "  tags    : %s" (String.concat ", " row.Ioc.Tags)) |> ignore

            sb.AppendLine(sprintf "  seen    : %s" (row.Ioc.SeenAt.ToString("o"))) |> ignore

            let e = row.Enrichment
            sb.AppendLine(sprintf "  country : %s" (fmtOpt e.GeoCountry)) |> ignore
            sb.AppendLine(sprintf "  city    : %s" (fmtOpt e.GeoCity)) |> ignore
            sb.AppendLine(sprintf "  asn     : %s" (fmtOpt e.Asn)) |> ignore
            sb.AppendLine(sprintf "  asn-org : %s" (fmtOpt e.AsnOrg)) |> ignore
            sb.AppendLine(sprintf "  rdns    : %s" (fmtOpt e.ReverseDns)) |> ignore
            sb.AppendLine(sprintf "  whois   : %s" (fmtOpt e.Whois)) |> ignore

            if not row.WhitelistReasons.IsEmpty then
                sb.AppendLine(
                    sprintf "  whitelist: %s" (String.concat "; " row.WhitelistReasons))
                |> ignore

            sb.AppendLine() |> ignore

        sb.ToString()

    let toJson (rows: ReportRow list) : JsonValue =
        rows
        |> List.map (fun row ->
            JsonValue.Record [|
                "kind", JsonValue.String (kindName row.Ioc.Kind)
                "value", JsonValue.String row.Ioc.Value
                "sources", JsonValue.Array (row.Ioc.Sources |> List.map JsonValue.String |> List.toArray)
                "tags", JsonValue.Array (row.Ioc.Tags |> List.map JsonValue.String |> List.toArray)
                "seen_at", JsonValue.String (row.Ioc.SeenAt.ToString("o"))
                "whitelisted", JsonValue.Boolean row.IsWhitelisted
                "whitelist_reasons",
                    JsonValue.Array (row.WhitelistReasons |> List.map JsonValue.String |> List.toArray)
                "geo_country", optStr row.Enrichment.GeoCountry
                "geo_city", optStr row.Enrichment.GeoCity
                "asn", optStr row.Enrichment.Asn
                "asn_org", optStr row.Enrichment.AsnOrg
                "reverse_dns", optStr row.Enrichment.ReverseDns
                "whois", optStr row.Enrichment.Whois
            |])
        |> List.toArray
        |> JsonValue.Array

type PipelineConfig = {
    GeoIp      : IGeoIp
    Asn        : IAsn
    ReverseDns : IReverseDns
    Whois      : IWhois
    Whitelist  : WhitelistRule list
}

module Pipeline =

    type RunDiagnostics = {
        InputCount        : int
        NormalizedCount   : int
        DroppedCount      : int
        /// Number of duplicates removed during deduplication
        /// (i.e. normalized.Length - deduped.Length).
        DuplicatesRemoved : int
    }

    let runWithDiagnostics
        (cfg: PipelineConfig)
        (rawFeeds: RawIoc list) : ReportRow list * RunDiagnostics =

        let enrich =
            Enrich.enrich cfg.GeoIp cfg.Asn cfg.ReverseDns cfg.Whois

        let normalized =
            rawFeeds
            |> List.choose Normalize.normalize

        let dropped = rawFeeds.Length - normalized.Length

        let deduped =
            normalized
            |> Dedup.deduplicate

        let duplicatesRemoved = normalized.Length - deduped.Length

        let rows =
            deduped
            |> Report.toRows enrich cfg.Whitelist

        rows, {
            InputCount = rawFeeds.Length
            NormalizedCount = normalized.Length
            DroppedCount = dropped
            DuplicatesRemoved = duplicatesRemoved
        }

    let run (cfg: PipelineConfig) (rawFeeds: RawIoc list) : ReportRow list =
        fst (runWithDiagnostics cfg rawFeeds)

module Demo =

    let rawFeeds : RawIoc list =
        let now = DateTime.UtcNow

        let feedA = [
            { Value = "1.2.3.4"; Kind = Some IPv4; Source = "feedA"
              Tags = ["malware"]; SeenAt = now }

            { Value = "evil[DOT]example.com"; Kind = None; Source = "feedA"
              Tags = []; SeenAt = now }

            { Value = "10.0.0.5"; Kind = Some IPv4; Source = "feedA"
              Tags = []; SeenAt = now }
        ]

        let feedB = [
            { Value = "1.2.3.4"; Kind = Some IPv4; Source = "feedB"
              Tags = ["c2"]; SeenAt = now }

            { Value = "hxxps://bad.example/path"; Kind = Some Url; Source = "feedB"
              Tags = ["phishing"]; SeenAt = now }

            { Value = "hxxps://bad.example/Path"; Kind = Some Url; Source = "feedB"
              Tags = ["phishing"]; SeenAt = now }
        ]

        let feedC = [
            { Value = "5d41402abc4b2a76b9719d911017c592"; Kind = Some Md5; Source = "feedC"
              Tags = ["malware"]; SeenAt = now }

            { Value = "www.example.com"; Kind = Some Domain; Source = "feedC"
              Tags = []; SeenAt = now }

            { Value = "2001:db8::1"; Kind = Some IPv6; Source = "feedC"
              Tags = ["infra"]; SeenAt = now }

            { Value = "http://evil.example/x"; Kind = Some Domain; Source = "feedC"
              Tags = []; SeenAt = now }

            { Value = "http://10.0.0.5/admin"; Kind = Some Url; Source = "feedC"
              Tags = []; SeenAt = now }
        ]

        feedA @ feedB @ feedC

    let buildConfig () : PipelineConfig =

        let geoData =
            Map.ofList [
                "1.2.3.4", ("RU", "Moscow")
                "10.0.0.5", ("US", "Palo Alto")
            ]

        let asnData =
            Map.ofList [
                "1.2.3.4", ("AS12345", "ExampleHosting LLC")
                "10.0.0.5", ("AS64500", "Private")
            ]

        let rdnsData =
            Map.ofList [
                "1.2.3.4", "c2.evil.example"
                "10.0.0.5", "localhost"
            ]

        let whoisData =
            Map.ofList [
                "evil.example", "Registrar: X; Created: 2024-01-01"
                "example.com", "Registrar: IANA; Created: 1995-08-14"
                "bad.example", "Registrar: Y; Created: 2023-11-11"
            ]

        let geo : IGeoIp =
            { new IGeoIp with
                member _.Lookup ip = Map.tryFind ip geoData }

        let asn : IAsn =
            { new IAsn with
                member _.Lookup ip = Map.tryFind ip asnData }

        let rdns : IReverseDns =
            { new IReverseDns with
                member _.Lookup ip = Map.tryFind ip rdnsData }

        let whois : IWhois =
            { new IWhois with
                member _.Lookup domain = Map.tryFind domain whoisData }

        let whitelist = [
            CidrRange ("10.0.0.0", 8)
            DomainSuffix "example.com"
            TagMatch "benign"
        ]

        {
            GeoIp = geo
            Asn = asn
            ReverseDns = rdns
            Whois = whois
            Whitelist = whitelist
        }

[<EntryPoint>]
let main argv =
    let cfg = Demo.buildConfig ()

    // --- CLI: --out <path> for output, positional args are input files. ---
    let mutable outPath : string option = None
    let inputs = ResizeArray<string>()
    let mutable i = 0
    while i < argv.Length do
        let a = argv.[i]
        if a = "--out" then
            if i + 1 < argv.Length && not (String.IsNullOrWhiteSpace argv.[i + 1]) then
                outPath <- Some argv.[i + 1]
                i <- i + 2
            else
                eprintfn "Missing value for --out"
                i <- i + 1
        elif a.StartsWith "--" then
            eprintfn "Unknown option: %s" a
            i <- i + 1
        else
            inputs.Add a
            i <- i + 1

    let parseOne (path: string) : Result<RawIoc list, ParseError> =
        let name = Path.GetFileName(path).ToLowerInvariant()
        let ext = Path.GetExtension(path).ToLowerInvariant()
        if name.Contains "stix" then
            Parsing.parseStixLite path path
        else
            match ext with
            | ".csv" -> Parsing.parseCsv path path
            | ".json" -> Parsing.parseJson path path
            // Fallback: try JSON, that's the safest default for an unknown feed.
            | _ -> Parsing.parseJson path path

    let rawFeedsResult : Result<RawIoc list, ParseError> =
        if inputs.Count = 0 then
            Ok Demo.rawFeeds
        else
            inputs
            |> Seq.fold (fun acc path ->
                match acc with
                | Error e -> Error e
                | Ok xs ->
                    match parseOne path with
                    | Ok ys -> Ok (xs @ ys)
                    | Error e -> Error e) (Ok [])

    match rawFeedsResult with
    | Error err ->
        eprintfn "Parse error: source='%s' path='%s' message='%s'"
            err.Source err.Path err.Message
        1
    | Ok rawFeeds ->
        let rows, diagnostics = Pipeline.runWithDiagnostics cfg rawFeeds

        printfn "%s" (Report.renderText rows)

        printfn
            "Pipeline: input=%d normalized=%d dropped=%d duplicates_removed=%d"
            diagnostics.InputCount
            diagnostics.NormalizedCount
            diagnostics.DroppedCount
            diagnostics.DuplicatesRemoved

        let outPath =
            match outPath with
            | Some p when not (String.IsNullOrWhiteSpace p) -> p
            | _ -> Path.Combine(Environment.CurrentDirectory, "report.json")

        try
            let jsonOut = Report.toJson rows
            File.WriteAllText(outPath, jsonOut.ToString(), Encoding.UTF8)
            printfn "JSON report written: %s" outPath
            0
        with
        | :? IOException as ex ->
            eprintfn "Could not write report '%s': %s" outPath ex.Message
            1
        | :? UnauthorizedAccessException as ex ->
            eprintfn "No permission to write report '%s': %s" outPath ex.Message
            1
        | ex ->
            eprintfn "Could not write report '%s': %s" outPath ex.Message
            1