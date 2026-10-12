"""Credential-conscious Xray validation error classification and private diagnostics."""
from __future__ import annotations

import os
from pathlib import Path


def classify(stderr: str) -> str:
    """Return a non-secret summary, never a line of stderr itself."""
    value = (stderr or "").lower()
    if "finalmask" in value:
        if any(word in value for word in ("unknown field", "unrecognized", "unsupported", "not supported", "unknown config")):
            return "finalmask-unsupported-or-outdated-core"
        return "finalmask-config-rejected"
    if "ech" in value:
        return "ech-config-rejected"
    if any(word in value for word in ("fragment", "maxsplit", "lengths", "delays")):
        return "fragment-config-rejected"
    if "unknown field" in value:
        return "unknown-json-field"
    if any(word in value for word in ("encryption", "vless", "vmess", "trojan")):
        return "protocol-config-rejected"
    if "not found" in value or "no such file" in value:
        return "missing-dependency-or-file"
    return "xray-config-rejected"


def write_first_error(folder: Path, diagnostics: str) -> Path:
    """Store raw core error locally, 0600 and only for first failure.

    Error messages may include destination names/credentials. Never print this
    file automatically or add it to a public issue without manual redaction.
    """
    path = Path(folder) / "xray-validation-error.log"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return path
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(diagnostics[:24000] if diagnostics else "Xray returned no diagnostic text.\n")
    return path
