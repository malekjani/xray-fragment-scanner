## New interactive entry point

Run `./bin/xray-finalmask-scanner` with no options to start the six-step
VLESS, VMess or Trojan assistant. See [WIZARD.md](WIZARD.md). Existing
non-interactive `--method optimize` and all its flags remain supported.

VMess Base64 QR links are accepted as input; variants are exported in
VMess AEAD URI syntax because the legacy format cannot reliably express fm.
Trojan retains its password, TLS, SNI, ECH, WebSocket and FinalMask
settings. Every link is decoded again for Xray configuration parity before
any network request. Supported fields are deliberately conservative.

# VLESS share-link optimization and analysis

## What is tested / exported

Method `optimize` takes a VLESS share-link, preserves its original values and tests candidate
modifications solely to **FinalMask TCP fragment** layers. Original `security`, `encryption`,
`fp`, `ech`, `sni`, `alpn`, WS `host`/`path`, TLS `pcs`/`vcn`, and any non-fragment TCP/UDP/QUIC
FinalMask layers remain unchanged. If an address is supplied with `--ip`, **only the actual
outbound address** changes, not SNI or WS Host. An original unmodified baseline is always tested.

The generator offers `--scan fragment`, `--scan finalmask` or `--scan both`:

* `fragment`: Cartesian product of `--packets`, `--lengths`, `--delays`, `--max-split` values;
  Xray FinalMask contains **one** fragment layer. Repeat each option to extend the grid.
* `finalmask`: multi-layer exact PattNG presets (`tlshello-0-len`, `tlshello`), plus an
  alternative without zero. Optionally add `--mask-file mask.json` or a custom second layer
  via `--layer2-packets`, `--layer2-lengths`, `--layer2-delays`, `--layer2-max-split`.
* `both`: two sets above together. Configurations are deduplicated by their exact FinalMask JSON.

Lists are **comma-delimited** within each CLI option: `--lengths '0,104,1'` becomes
`["0","104","1"]`, not a CSV row or numeric range. An element may itself be a range,
for example `--delays '0,1-5'`. The **last** lengths element must not start at zero.
`lengths` and `delays` may have different lengths. Presets preserve exact integer-range strings.

Warning: a leading zero with `packets=tlshello` sends an empty TLS record in some core builds,
which violates RFC TLS framing and can fail on particular servers. Zero `maxSplit` means
unlimited splitting; zero `delays` does not guarantee OS-level packets are separated.

## Files and traceability

Every candidate is assigned one identifier such as `OPT-0007` and passes:

1. Build full runnable Xray JSON; preserve original share-link fields except selected mask.
2. Serialize modified `fm` as a percent-encoded JSON property and generate VLESS share-link.
3. Parse generated link back into JSON. Assert outbound settings and stream settings match
   tested JSON **exactly**. Abort entire run rather than export mismatched candidates.
4. Call `xray run -test -c` on that JSON before launching Xray for HTTPS proxy checks.
5. Keep rows and links one-to-one using ID and SHA-256 of the complete URI.

Outputs (all user-only):

| File | Contents |
|---|---|
| `results.csv` | each tested candidate in scan order; exact JSON arrays for all fragment layers, `fm` JSON, TLS/ECH, successes, average and P95 |
| `ranked.csv` | same rows ranked by success fraction (descending), then P95/mean HTTPS request times (ascending) |
| `links.csv` | `id,link` pairing for every trial, including failures and baseline |
| `links.txt` | importable VLESS URIs, one per trial in the same order as `results.csv` |
| `manifest.jsonl` | per-candidate exact FinalMask, successful HTTPS request times, link SHA-256 and ID |
| `best-vless.txt` | top **fully successful** share-link, only after actual networking succeeds |
| `best-config.json` | exact winning tested JSON, including credentials; no fake winners in dry-run |
| `summary.json` | scan flags, count, ranking methodology and winning ID (if any) |

`links.csv`, `links.txt`, `best-vless.txt`, and `best-config.json` contain private credentials.
The results/manifest may contain sensitive Host/SNI/FinalMask data. Never commit these.
Default output path is private and all outputs are `0600`; folder mode is `0700`.

### Examples

```bash
./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/private-vless.txt --requests 5 --limit 25

./bin/xray-finalmask-scanner --method optimize --scan both \
  --link-file ~/private-vless.txt --packets tlshello --lengths '0,104,1' \
  --lengths '6,98,1' --delays '0' --max-split '0' \
  --layer2-lengths '114,1' --layer2-delays '1' --layer2-max-split '11' --all

./bin/xray-finalmask-scanner --method optimize \
  --link-file ~/private-vless.txt --dry-run --limit 10
```

`--all` overrides the sampling limit; the default is 25 variants. Start with a short run.
For a meaningful network comparison, repeat full-success tests at different times and
consider speed/packet-loss measurements. The initial probe sends HTTPS requests, not ICMP.

## Compatibility and limits

Official FinalMask documentation: https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/transports/finalmask.md

Official Xray sharing proposal (section 4.3.20):
https://github.com/XTLS/Xray-core/discussions/716

The interoperable share-link `fm` value is the JSON **property**
`"finalmask":{...}` percent-encoded with URI-component escaping (consistent with PattNG
exports), rather than a vendor-specific legacy `freedom.fragment` URL flag.
A client must actually support parsing this `fm` parameter; Xray JSON tests alone cannot
prove that every GUI imported it correctly. Verify visually in the target client.

The older `freedom.fragment` outbound uses `sockopt.dialerProxy` and is not encoded
in the standard `fm` link. For user-requested **importable VLESS links**, all optimized
fragment candidates therefore use modern FinalMask fragment layers.

Unknown URI query parameters (for example XHTTP `extra` or vendor-specific fields)
are rejected by optimize rather than silently disappearing from the tested JSON.
No real-world connectivity is claimed by offline candidate-generation tests.
