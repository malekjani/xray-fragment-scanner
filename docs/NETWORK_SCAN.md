# User-defined IP, ECH and PattNG FinalMask scanning (October 2026)

The seven IPs and eighteen resolvers from the original writeup are **examples**,
not a whitelist or hardcoded working set. The CLI accepts IPs, IPv6, hostnames,
CIDR ranges, complete ECH expressions and ECH lookup domain/resolver pairs.

## How to run

```sh
# Interactive: menu 2 for ECH, 3 for FinalMask, then enter a VLESS link
./bin/xray-finalmask-scanner

# Read link ECH + seven original example IPs, with optional interactive prompts
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt

# User-supplied addresses and ECH expressions (no example IPs)
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt \
  --ip 188.114.97.1 --ip 198.51.100.2 \
  --ech 'cloudflare-ech.com+udp://9.9.9.9' \
  --ech 'crypto.cloudflare.com+https://1.1.1.1/dns-query' \
  --all --no-prompt

# Use lists from files; ECH domain and resolver cross-product is optional
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt \
  --ip-file ./addresses.txt --ech-file ./ech-list.txt \
  --ech-domain crypto.cloudflare.com \
  --ech-resolver 'https://1.1.1.1/dns-query' --no-prompt

# Re-enable the historical 18 resolver samples (using the domain from your link)
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt \
  --example-ech --all --no-prompt

# Exact PattNG FinalMask and Firefox cipher presets
./bin/xray-finalmask-scanner --method irancell --link-file ~/private-vless.txt \
  --ip 188.114.97.1 --all --no-prompt

# Generate candidate configurations without network access or Xray
./bin/xray-finalmask-scanner --method ech --link-file ~/private-vless.txt \
  --dry-run --limit 10 --no-prompt
```

Address file: one IP/hostname/CIDR per line, comments begin with `#`.
ECH file: **complete** Xray ECHConfigList expressions, one per line.
CLI options `--ip`, `--ech`, `--ech-domain`, `--ech-resolver` are repeatable.
Bare resolver IPs become `udp://IP`. `--example-ips` appends example IPs
even when custom IPs are provided; `--example-ech` opts into the former
18-resolver sample using your link's ECH lookup domain. If the VLESS link
has no ECH and none is supplied, a *single, unverified* sample expression is used.
`--no-link-ech` excludes the source link's ECH from candidate variants.
Each scan keeps the untouched link as the baseline; it is never automatically
rewritten in the original profile.

## Exact PattNG resources

The supplied PattNG `FieldPresetsTest.kt` and `strings.xml` contain:
- `profiles/pattng-tlshello-0-len.json`: first fragment
  `tlshello / lengths=[0,104,1] / delays=[0] / maxSplit=0`, then
  `1-1 / lengths=[114,1] / delays=[1] / maxSplit=11`.
- `profiles/pattng-tlshello.json`: first fragment
  `tlshello / lengths=[6,98,1] / delays=[0] / maxSplit=0`, then same second.
- `profiles/pattng-real-firefox-cipherSuites.txt`: **12 exact suites**.

The Irancell-mode scan evaluates both literal PattNG masks, a zero-free
alternative and no mask; it uses `fingerprint=unsafe` to test native Go TLS
with either its default cipher set or the exact PattNG cipher list.
`unsafe` here does **not** disable certificate validation. A non-final zero
in `lengths` is allowed under current upstream FinalMask docs, but may fail
for specific peers/networks. It must be actually tested.

## Xray upstream compatibility (reviewed 2026-10-12)

- FinalMask: https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md
  (ordered TCP masking layers, `packets`, `lengths`, `delays`, `maxSplit`).
- TLS and ECH: https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md
  (`echConfigList` supports a static ECHConfig, `udp://`, DoH or
  `domain+resolver`, and offers `echSockopt` for DNS connection settings).
- uTLS can override other TLS settings; use native TLS when evaluating ciphers.
  ALPN has special treatment for WebSocket/HTTPUpgrade using ECH; the scanner
  preserves the source-link ALPN rather than guessing.
- Xray-core stable `v26.3.27` includes FinalMask and TLS ECH updates;
  the newer `v26.10.10` published on Oct 10 is a **prerelease**.
  https://github.com/XTLS/Xray-core/releases

A config that passes JSON parsing or Xray `run -test` has **not necessarily**
completed TLS negotiation or an HTTPS request. Only actual successful requests
count in latency/success statistics. All results are network-specific.

## Output privacy

The scanner does not run as root, install/update Xray or modify systemd.
It binds a temporary proxy to 127.0.0.1. Results go to a private folder:
CSV omits UUIDs, but the 0600 JSON example/best configs contain credentials.
Never commit config outputs or publish a personal VLESS link. A dry run never
reports actual connection success. The selection ranks success rate before
average HTTPS request time; that time is not ICMP ping. The test environment
could not run live Iranian mobile-network connectivity probes.
