# Configurable IP / ECH / PattNG FinalMask scanning

This module is independent of the legacy fragment scanner. It does **not**
install packages, stop system services, request root privileges, or automatically
change a production profile. It loads a VLESS link (including `ech`, `fm`,
`encryption`, SNI, Host and path) and probes each configuration with a local
Xray instance. Neither the original seven IPs nor the eighteen DNS resolvers
are whitelists, guarantees, or claims of being reachable.

## Interactive mode

```bash
./bin/xray-finalmask-scanner
# 2 = IP / ECH
# 3 = IP / FinalMask + native TLS / cipherSuites
```

The program asks for a VLESS link with hidden terminal echo, then offers to
add or replace candidate IP/host/CIDR addresses. Mode 2 additionally offers
custom **full ECH expressions**, ECH lookup domains, DNS resolver URIs, and
an optional 18-resolver historical sample set. Enter accepts the defaults.
An interactive session is detected only when stdin is a TTY. In scripts, use
`--no-prompt` and pass values using CLI options or files.

## ECH input logic

- Original `ech=` from the VLESS link is included **verbatim** as a candidate,
  unless `--no-link-ech` is requested. Original full VLESS configuration is
  always evaluated as a baseline.
- If no custom IPs are supplied, the seven example Cloudflare IPs are offered.
  Explicit `--ip`, `--ip-file` replace those examples, unless `--example-ips`
  is set. Hostnames, IPv4, IPv6 and CIDR ranges work (up to 4096 expanded IPs).
- Multiple `--ech` or lines of `--ech-file` accept **complete Xray expressions**
  such as `cloudflare-ech.com+udp://1.1.1.1`, `udp://8.8.8.8`,
  `crypto.cloudflare.com+https://1.1.1.1/dns-query` or an ECHConfig blob.
- `--ech-domain` and `--ech-resolver` produce a cross product. Resolvers can
  be `udp://`, `tcp://`, `https://`/DoH, `h2c://`, etc. A bare resolver IP
  expands to `udp://IP`. When no domain is supplied, reuse the named lookup
  domain from the VLESS link; if the link uses bare `udp://`, use bare lookups.
- `--example-ech` explicitly enables the previous eighteen *example* resolver
  addresses. Crucially, it reuses **the ECH domain in the VLESS link** rather
  than silently hardcoding `cloudflare-ech.com`.
- With no ECH link or custom expression, the single demonstration default is
  `cloudflare-ech.com+udp://1.1.1.1`. This is not a verified working choice.
- Candidate generation deduplicates exact values, includes the baseline, and
  uses deterministic IP-balanced subsampling unless `--all` is requested.

### Examples

```bash
# Auto: VLESS ECH + example IPs, with opportunity to add values interactively
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt

# Use IPs/CIDRs from a custom file, two complete ECH expressions, no samples
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt \
    --ip-file ./addresses.txt \
    --ech 'cloudflare-ech.com+udp://9.9.9.9' \
    --ech 'crypto.cloudflare.com+https://1.1.1.1/dns-query' \
    --all --no-prompt

# Supply names and resolvers for combinations based on YOUR network
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt \
    --ech-domain cloudflare-ech.com --ech-domain crypto.cloudflare.com \
    --ech-resolver udp://9.9.9.9 \
    --ech-resolver https://1.1.1.1/dns-query --no-prompt

# Optional historical 7 × 18 sample: adapts the domain to `ech=` in the link
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt \
    --example-ech --all --no-prompt

# Test exact PattNG presets, with user-supplied address. No root/systemd changes
./bin/xray-finalmask-scanner --method irancell --link-file ~/private-vless.txt \
    --ip 188.114.97.1 --all --no-prompt

# Offline check of inputs and candidate JSON (does not run xray or curl)
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt \
    --ech-file ./ech-list.txt --dry-run --limit 12 --no-prompt
```

**File example `addresses.txt`**: one address, hostname or CIDR per line.
**File example `ech-list.txt`**: one *complete* `echConfigList` per line.
Lines starting with `#` are comments. Do not post your VLESS UUID/publicly.

## Exact PattNG values

The user-supplied PattNG `FieldPresetsTest.kt` and app `strings.xml` agree
on the following literal values, now stored as project fixtures:

- `profiles/pattng-tlshello-0-len.json`:
  `tlshello lengths=["0","104","1"] delays=["0"] maxSplit="0"`, followed
  by `1-1 lengths=["114","1"] delays=["1"] maxSplit="11"`.
- `profiles/pattng-tlshello.json`: first length sequence `["6","98","1"]`,
  followed by the same second fragmentation layer.
- `profiles/pattng-real-firefox-cipherSuites.txt`: exact 12 colon-delimited
  cipher suites from the app resources, **not an approximation**.

The Irancell experiments include exact `tlshello-0-len`, exact `tlshello`,
a zero-free variant and no TCP fragment layer. **By default** source TLS,
ECH, fingerprint and ciphers are preserved. For a deliberate PattNG native
TLS experiment, select `--tls-profile pattng-unsafe`; this compares the
native-default cipher set with the literal PattNG Firefox cipher list but
**never strips ECH**. `fingerprint="unsafe"` is **not** `allowInsecure=true`;
certificate verification stays as defined by the imported link. Failure of one preset
is reported as a failure; zero length is supported by the documented FinalMask
syntax but can have network-specific side effects. FinalMask is applied at
`outbounds[].streamSettings.finalmask` (not the deprecated Freedom outbound
fragment syntax).

## Upstream Xray-core checks (reviewed 2026-10-12)

- [Xray FinalMask docs](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md):
  `tcp` is an ordered list of layers; `fragment` accepts `packets`, `lengths`,
  `delays`, `maxSplit`; non-final `0` in `lengths` is allowed. `0` in `maxSplit`
  means unlimited. `delays` are milliseconds. TCP and UDP have different masks.
- [Xray TLS/ECH docs](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md):
  `echConfigList` can be a static ECHConfig blob, a DNS resolver URI or
  `domain+resolver`. DNS lookup can use UDP, DoH, etc., and respects TTL.
  `echSockopt` independently adjusts socket options for ECH DNS.
- With uTLS fingerprints enabled, `cipherSuites` may be overridden. Use
  `fingerprint="unsafe"` to assess PattNG's cipher list with native TLS.
  Browser Dialer is a separate option; TLS mimicry is not complete.
- Modern Xray handles WebSocket/HTTPUpgrade with ECH and special ALPN rules;
  keep the VLESS-supplied ALPN unchanged rather than automatically modifying it.
- [Xray core releases](https://github.com/XTLS/Xray-core/releases): latest
  **non-prerelease** retrieved at the time of review was `v26.3.27`;
  `v26.10.10` (2026-10-10) is a newer **prerelease**. The Xray 26.3.27 release
  expanded FinalMask and ECH semantics, including an ECH query policy change.

Runtime support may depend on the Xray binary's version and how the server/CDN
is configured. A passing JSON parse or Xray `run -test` is *not* proof that a
particular ECH resolver or FinalMask preset establishes a working TLS session.
An HTTP 2xx/3xx through the temporary local proxy is counted as success.
Average end-to-end HTTP request time is **not** an ICMP ping. The experiment
ranks success rate first, then p95 and mean HTTP latency; it cannot predict other
clients, paths or future censorship behavior.

## Output and privacy

Temporary Xray binds to localhost only. Per-candidate config has mode 0600;
results directory mode 0700. `results.csv` now records exact mask JSON,
fragment arrays, ECH/fingerprint and request statistics but not UUID/full URI.
`links.csv` and `links.txt` contain complete sensitive URI credentials; use
`id` to join every row to its exact URI and `manifest.jsonl`. `example-config.json` and
`best-config.json` (only after actual successful probes) include credentials:
do **not** commit or share them. Only the run's best *tested* candidate is
selected; dry runs do not claim success. Cap candidate matrices using
`--limit`; `--all` is potentially expensive.

## Validation limits

Unit tests check value parsing, URI preservation, exact PattNG fixtures,
custom and sample matrix generation, privacy of output and dry-run. A live
Xray-core runtime binary and local Iranian carrier networks were not available
in the build environment, so no end-to-end connectivity claims are made.

## October 2026 security and round-trip update

Network scanners (`--method irancell` / `--method ech`) now export `results.csv`,
`ranked.csv`, `links.csv`, `links.txt` and `manifest.jsonl` with stable NET-IDs.
Each candidate VLESS URI is re-parsed and compared to its exact tested Xray
JSON before any scan. Default TLS/ECH/fingerprint values are preserved; only
requested variables differ. `--ech-chrome` and `--tls-profile pattng-unsafe`
are explicit choices. ECH remains in place even in the opt-in unsafe profile.
`best-link.txt` requires verified live success. See [LEGACY-ECH.md](LEGACY-ECH.md).
