# IP/ECH + IP/FinalMask experiments

## Prerequisites

- Linux with Python 3.9+, curl and an **up-to-date Xray-core** in PATH
  (or `/usr/local/bin/xray`). Existing three legacy modes have separate
  installation behavior.
- A **working, authorized VLESS URL** for which the edge IP can be changed.
  Replacing an arbitrary server's address with Cloudflare IPs will **not**
  make it work unless its TLS/Host/SNI and CDN deployment fit those addresses.
- TLS and a compatible Cloudflare-routed endpoint for the ECH scan.
- Run this module without `sudo`, unless local file permissions require it.

## Interactive run

```bash
chmod +x bin/xray-finalmask-scanner
./bin/xray-finalmask-scanner
# Choose 2 (ECH) or 3 (Irancell).
```

The input VLESS URI is read with hidden terminal echo; no credentials are put
in the CLI arguments. Results (including `best-config.json` with your UUID)
are written under `~/.local/share/xray-finalmask-scanner/` with directory
mode 0700 and config file mode 0600.

## CLI examples

```bash
# Save your personal VLESS URI to an untracked private file:
chmod 600 ~/my-vless.txt

# Rightel / MCI / similar network behavior: 21 sampled combinations + baseline
./bin/xray-finalmask-scanner --method ech --link-file ~/my-vless.txt

# Full ECH scan (7 × 18 + baseline): 127 configurations, each 3 real requests
./bin/xray-finalmask-scanner --method ech --link-file ~/my-vless.txt --all

# Irancell / similar network behavior: 14 sampled combinations + baseline
./bin/xray-finalmask-scanner --method irancell --link-file ~/my-vless.txt

# Dry-run the first 8 profiles: does not start Xray or run network requests
./bin/xray-finalmask-scanner --method irancell --link-file ~/my-vless.txt --dry-run --limit 8

# Exact PattNG JSON and ciphers *if you have exported them*, one per file
./bin/xray-finalmask-scanner --method irancell \
  --link-file ~/my-vless.txt \
  --finalmask-json ./my-pattng-mask.json --cipher-file ./my-pattng-ciphers.txt

# Test the experimental zero-length mask (off by default)
./bin/xray-finalmask-scanner --method irancell \
  --link-file ~/my-vless.txt --experimental-zero
```

Flags: `--requests`, `--timeout`, `--seed`, `--limit`, `--all`, `--dry-run`,
`--url`, `--output`, `--xray`, `--experimental-zero`, `--finalmask-json`,
`--cipher-file`.

## What is actually measured?

Each candidate runs in a separate temporary Xray subprocess that listens
only on 127.0.0.1 using a free local port. `curl` tests real HTTPS GET through
that proxy (`https://www.gstatic.com/generate_204` by default). HTTP 2xx/3xx
is a success; timeouts, invalid configs and other statuses fail. All requests
must succeed to qualify as 'best'. `avg_ms` is total HTTP-request latency,
**not** ICMP ping, and is affected by the target website and route.

Only the sampled candidates are compared unless `--all` is used. The initial
candidate is the original URL unchanged, to provide a reference point.

The output CSV does not contain the UUID, TLS secrets, or full URL. The output
JSON configuration **does** contain credentials: do not post it publicly.

## Technical compatibility and caveats

1. **ECH**: candidate format is `cloudflare-ech.com+udp://DNS-IP`, inserted as
   `tlsSettings.echConfigList`; `fingerprint=chrome`. Changing DNS resolver can
   change availability but cannot guarantee ECH records or bypass restrictions.
   UDP/53 to those DNS providers must be reachable. The 18 addresses follow
   the user's input; there is no guarantee that all return the required record.
2. **IP substitution**: `outbounds[0].settings.address` changes, while
   `tlsSettings.serverName`, `wsSettings.headers.Host` and `wsSettings.path`
   stay unchanged. This separation is required for many CDN connections.
3. **Irancell**: `fingerprint=unsafe` uses native Go TLS, NOT disabled TLS
   verification. The bundled `firefox-like-approx` list comprises standard Go
   TLS 1.2 cipher-suite names; it has not been proven byte-for-byte identical
   to PattNG's `real_firefox_cipherSuites` preset. Bring the exact string via
   `--cipher-file` to evaluate that exact option.
4. **tlshello-0-len** is a PattNG UI preset name, not an Xray FinalMask `type`.
   Exact mapping has not been independently verified. The scanner ships a
   **zero-free** two-fragment profile and an opt-in **experimental zero** mask
   adapted from a public sample (which **may not** be the PattNG preset).
   Xray issue [#6724](https://github.com/XTLS/Xray-core/issues/6724)
   documents handshake failures on some zero-length tlshello fragments.
   Paste an exact FinalMask JSON export into `--finalmask-json` rather than
   assuming the public sample is equivalent.
5. **WebSocket ALPN**: Some URL exports set `alpn=h2` with `type=ws`; server
   support for WS over this ALPN varies. Scanner does not silently change it.
6. **Not a real-world validation in this ZIP**: JSON structure and dry-run
   candidate generation were tested. No Iranian carrier connectivity or Xray
   runtime integration was available in the build environment. Use actual
   network results and logs to determine what works.

Upstream references:
- https://github.com/XTLS/Xray-core/blob/main/transport/internet/tls/ech.go
- https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/tls.md
- https://github.com/XTLS/Xray-core/issues/6724
