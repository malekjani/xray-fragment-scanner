"""Credential-safe diff of requested and generated Xray connection semantics.

Effective/on-wire effects are NEVER inferred from JSON differences. This is a
preview; real core and network evidence must be recorded separately.
"""
from __future__ import annotations
from network_scan import proxy


SENSITIVE=('password','id','encryption','echConfigList','publicKey','shortId',
           'serverName','host','path','address','certificate','token')


def _flatten(value,prefix=''):
    # Preserve ordered FinalMask arrays and other lists as atomic: order matters.
    if isinstance(value,dict):
        out={}
        for k,v in value.items():
            out.update(_flatten(v,prefix+'.'+k if prefix else k))
        return out
    return {prefix: value}


def _public_value(path,value):
    if any(key.lower() in path.lower() for key in SENSITIVE):
        return '[set]' if value not in (None,'',[],{}) else '[unset]'
    if path.startswith('streamSettings.finalmask'):
        # Fragment arrays aren't credentials, but Header-Custom may contain payloads.
        if path.endswith('.tcp') and isinstance(value,list):
            return [layer.get('type','unknown') if isinstance(layer,dict) else 'invalid' for layer in value]
        return '[configured]' if value else '[unset]'
    return value


def effective_preview(original: dict, candidate: dict, requested_changes=None):
    a=proxy(original); b=proxy(candidate)
    base=_flatten({'settings':a['settings'],'streamSettings':a['streamSettings']})
    test=_flatten({'settings':b['settings'],'streamSettings':b['streamSettings']})
    modified=[]
    for key in sorted(set(base)|set(test)):
        if base.get(key)!=test.get(key):
            modified.append({'path':key,'before':_public_value(key,base.get(key)),
                             'after':_public_value(key,test.get(key))})
    return {
        'requested':list(requested_changes or []),
        'generated':modified,
        'generated_count':len(modified),
        'core_validation':'PENDING',
        'runtime_effect':'NOT_OBSERVED',
        'note':'Changed JSON fields are not proof that Xray uses them on wire. Browser Dialer may override TLS.',
    }
