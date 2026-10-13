"""Shared legacy-style FinalMask results projection for V8 CLI, web and CSV.

Never call proxied HTTPS time 'ICMP ping'. One immutable tested candidate ID maps
back to exactly one full mask JSON and share link in the private manifest.
"""
from __future__ import annotations

import csv
import io
import json

HEADERS = ('Instance', 'Packets', 'Length', 'Delay', 'Max Split',
           'Average Response (ms)', 'Success', 'Status')
FIELDS = ('instance', 'packets', 'length', 'delay', 'max_split',
          'average_response_ms', 'success', 'status')


def _layers(mask_raw):
    try:
        mask = json.loads(mask_raw) if isinstance(mask_raw, str) else mask_raw
        return [x.get('settings', {}) for x in (mask or {}).get('tcp', [])
                if isinstance(x, dict) and x.get('type') == 'fragment']
    except (ValueError, TypeError, AttributeError):
        return []


def _val(value):
    if isinstance(value, list):
        return ','.join(str(x) for x in value)
    return str(value) if value is not None else '-'


def project(row):
    """Export each ordered TCP fragment layer, not just the first one."""
    layers = _layers(row.get('finalmask_json'))
    def stack(name):
        if not layers:
            return 'Original' if row.get('profile') == 'baseline' else '—'
        return ' / '.join(_val(layer.get(name)) for layer in layers)
    rate = row.get('success_rate')
    count = row.get('successes')
    req = row.get('requests')
    success = f'{count}/{req}' if count is not None and req is not None and str(req) != '' else '—'
    avg = row.get('avg_ms')
    return {
        'instance': row.get('id', '—'), 'packets': stack('packets'),
        'length': stack('lengths'), 'delay': stack('delays'),
        'max_split': stack('maxSplit'),
        'average_response_ms': f'{float(avg):.2f}' if avg not in ('', None) else '—',
        'success': success, 'status': row.get('status', 'UNTESTED'),
    }


def best_three(rows):
    """Lowest *observed* average among successful candidates, regardless of status.

    Status is retained; no SCREENED candidate is presented as a verified winner.
    """
    eligible = [r for r in rows if int(r.get('successes') or 0) > 0
                and r.get('avg_ms') not in ('', None)]
    return sorted(eligible, key=lambda r: (float(r['avg_ms']), str(r.get('id', ''))))[:3]


def ascii_table(rows):
    values = [[project(r)[k] for k in FIELDS] for r in rows]
    widths = [max(len(HEADERS[i]), *(len(str(r[i])) for r in values)) if values
              else len(HEADERS[i]) for i in range(len(HEADERS))]
    rule = '+' + '+'.join('-' * (w + 2) for w in widths) + '+'
    def fmt(record):
        return '|' + '|'.join(' ' + str(val).ljust(w) + ' ' for val, w in zip(record, widths)) + '|'
    return '\n'.join([rule, fmt(HEADERS), rule,
                      *(fmt(row) for row in values), rule])


def text_report(rows):
    lines = ['FinalMask / Fragment — complete instance results',
             'Average Response = proxied HTTPS request time; NOT ICMP ping.',
             'Multi-layer Fragment is ordered left-to-right with / separators.',
             ascii_table(rows), '', 'Top three lowest average response times:']
    winners = best_three(rows)
    if winners:
        lines.append(ascii_table(winners))
        if not all(r.get('status') == 'VERIFIED' for r in winners):
            lines.append('These are measured candidates, NOT verified winners; check Status.')
    else:
        lines.append('No successful HTTPS measurements; no fastest candidates available.')
    return '\n'.join(lines)


def csv_text(rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(project(row) for row in rows)
    return output.getvalue()
