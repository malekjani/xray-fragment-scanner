"""Compatibility bridge for V8's new lib/compatibility package.

Keep the old import path for existing V8 tests and third-party draft callers.
"""
from compatibility import Finding, validate, safe_summary, core_capabilities, effective_preview
