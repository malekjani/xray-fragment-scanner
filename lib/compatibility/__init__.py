"""Version-aware Xray V8 compatibility checks and effective-change previews.

Static documentation rules are *not* evidence of on-wire behavior. A successful
`xray run -test` only proves syntactic/core configuration acceptance.
"""
from .rules import Finding, validate, safe_summary
from .versioning import core_capabilities, parse_xray_version
from .diff import effective_preview
__all__ = ['Finding','validate','safe_summary','core_capabilities','parse_xray_version','effective_preview']
