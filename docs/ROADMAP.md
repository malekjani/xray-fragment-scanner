# Roadmap

## Done

- Modular project structure
- Finalmask fragment scanner
- Finalmask `header-custom + fragment` mode
- Legacy fragment mode
- VLESS link to `config.json` generation
- REALITY parsing with `password` support for newer Xray configs

## Next

### 1. Header profile scanner

Add a new mode:

```text
finalmask-header-profile-scan + fragment
```

This should test multiple header packets, not just one fixed header.

### 2. UDP noise

Add config generation for:

```text
finalmask.udp.noise
```

A separate UDP benchmark is needed because the current `curl` benchmark is TCP/HTTP-based.

### 3. browserDialer

Add an optional browserDialer mode for supported transports such as XHTTP/WebSocket.

### 4. Non-interactive CLI flags

Example future usage:

```bash
sudo ./bin/xray-finalmask-scanner \
  --mode finalmask-header-fragment \
  --instances 30 \
  --timeout 10 \
  --requests 5 \
  --http-port 10809
```

## 2026-10 additions

- [x] Isolated non-root `IP + ECH` scan using the supplied Cloudflare IP/DNS lists.
- [x] Isolated `IP + unsafe TLS + FinalMask + cipherSuite` scan.
- [x] Exact finalmask/cipher imports for PattNG (if exported).
- [x] Real HTTP pass/fail rates, CSV, private best-config JSON, dry-run tests.
- [ ] Verify exact PattNG `tlshello-0-len` and `real_firefox_cipherSuites` values
      against PattNG source/export, rather than assuming a public sample.
- [ ] Validate on actual Iran mobile networks and tune timeouts/weights.
- [ ] Add transport-aware throughput and jitter tests.

## Latest improvements (October 2026)

- [x] Step-by-step VLESS, VMess (AEAD / legacy Base64 QR) and Trojan wizard.
- [x] Optimizer preserving TLS/ECH/WS/etc. with multi-layer FinalMask fragment arrays.
- [x] Unique share link + ID + CSV ranking + JSONL metrics for every optimization candidate.
- [x] IP/ECH scanner preserves original fingerprint and FinalMask by default; optional `--ech-chrome`.
- [x] Irancell scanner preserves ECH, fingerprint and original non-Fragment masks by default; explicit `--tls-profile pattng-unsafe`.
- [x] IP/ECH and Irancell modes export verified per-ID VLESS links and detailed CSV/JSONL tables.
- [x] Legacy Bash VLESS parser retains ECH/ciphers/certificate pinning and existing FinalMask.
- [x] Exact PattNG `tlshello-0-len` and Firefox cipher presets imported from supplied resource/test definitions.
- [ ] Run on multiple real ISPs / networks and record success, throughput and jitter over time.
- [ ] Validate import compatibility with the exact app/core versions used in production.
