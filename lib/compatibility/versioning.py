"""Conservative capability metadata for a *locked* Xray executable version.

Only compare known official version formats. Unknown versions remain experimental;
a new prerelease cannot inherit unverified capabilities merely by its number.
"""
from __future__ import annotations
import re

# Source: XTLS/Xray-core tag v26.10.10 transport/internet/finalmask/fragment/config.proto,
# compared with v26.3.27 infra/conf/transport_internet.go.
# New prereleases still require explicit run -test and runtime verification.
DOCUMENTATION = {
    'fragment_arrays': 'https://github.com/XTLS/Xray-core/blob/v26.10.10/transport/internet/finalmask/fragment/config.proto',
    'legacy_fragment': 'https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/transport_internet.go',
}


def parse_xray_version(raw: str | None):
    if not raw: return None
    m=re.search(r'\bXray\s+(\d{2})\.(\d{1,2})\.(\d{1,2})\b',raw,re.I)
    if not m: return None
    return tuple(int(m.group(i)) for i in (1,2,3))


def core_capabilities(identity: str | None):
    version=parse_xray_version(identity)
    if version is None:
        return {'version':'unknown','fragment_arrays':'unverified','reason':'Exact Xray version has not been checked yet; Xray validation is mandatory.'}
    recognized=version >= (26,10,10)
    return {'version':'.'.join(map(str,version)),
            'fragment_arrays':'documented-runtime-validation-required' if recognized else 'unsupported-known-old-core',
            'reason':'Fragment lengths[]/delays[] are documented for Xray v26.10.10; new releases still require real validation.'
                     if recognized else 'This Xray version predates the documented array-based FinalMask fragment schema.'}
