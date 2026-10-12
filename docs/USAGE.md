# Usage / راهنمای اجرا

**Recommended / پیشنهاد اصلی:** use `./bin/xray-finalmask-scanner` without arguments.
It prompts for a VLESS / VMess / Trojan share link, asks for Fragment/FinalMask
parameters and writes verified per-candidate links plus CSV/JSONL analytics.
اجرای بدون پارامتر، راهنمای مرحله‌ای را باز می‌کند و برای هر آزمون لینک و جدول
جداگانه می‌سازد. برای آزمایش واقعی، `xray` و `curl` باید نصب باشند.

```bash
./bin/xray-finalmask-scanner

# Safe CLI default: preserve ECH / Fingerprint / TLS / WS
./bin/xray-finalmask-scanner --method irancell --link-file ~/private-link.txt \
  --ip example.net --requests 5 --timeout 10 --no-prompt

# Deliberately change to PattNG-like native TLS (ECH remains intact)
./bin/xray-finalmask-scanner --method irancell --link-file ~/private-link.txt \
  --ip example.net --tls-profile pattng-unsafe --no-prompt

# Legacy administrative workflow (root; may affect system Xray)
sudo ./bin/xray-finalmask-scanner --legacy-menu
```

The historical Legacy mode retains `ech`, `fp`, `alpn`, `cs`, `pcs`, `vcn`
and `fm` while scanning `freedom.fragment` values. It does not generate
per-candidate share links; use `optimize` to obtain them. More details:
[README](../README.md), [Wizard](WIZARD.md), [Optimizer](OPTIMIZE.md),
[Network scanner](NETWORK_SCAN.md), [Legacy/ECH fixes](LEGACY-ECH.md).
