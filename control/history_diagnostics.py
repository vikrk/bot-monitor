"""Compact diagnostic fields for check history; no credentials or commands."""
import json
import re

FIELDS = ('ok', 'exit', 'http', 'http_status', 'exit_code', 'elapsed_ms', 'error_detail', 'error', 'reason',
          'total_seconds', 'tls_elapsed_seconds', 'rcode', 'answers', 'sent', 'received', 'average_ms', 'certificate_verified', 'cert_days_remaining')

def text(value, limit=1024):
    value = str(value)
    value = re.sub(r'(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----', '[REDACTED]', value)
    value = re.sub(r'(?i)Bearer\s+\S+', 'Bearer [REDACTED]', value)
    value = re.sub(r'\b(?:sk[-_]|ghp_|github_pat_|gsk_)[A-Za-z0-9_-]{12,}', '[REDACTED]', value)
    value = re.sub(r'\b\d{5,15}:[A-Za-z0-9_-]{20,}\b', '[REDACTED]', value)
    value = re.sub(r'(?i)(api[_-]?key|password|passwd|token|secret|authorization)([\"\s]*[=:][\"\s]*)[^,\s\"}]+', r'\1\2[REDACTED]', value)
    value = re.sub(r'(https?://)[^\s/]+:[^\s/@]+@', r'\1[REDACTED]@', value)
    value = re.sub(r'([?&](?:[^=&\s]+)=)[^&\s]+', r'\1[REDACTED]', value)
    value = re.sub(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b', '[ID]', value)
    return value[:limit]

def collect_diagnostics(result):
    rows = []
    def visit(value, path=(), depth=0):
        if depth > 10 or len(rows) >= 200 or not isinstance(value, dict):
            return
        fields = {k: value[k] for k in FIELDS if k in value and isinstance(value[k], (str, int, float, bool, type(None)))}
        if fields:
            row = {'check': text('/'.join(p for p in path if p not in ('report', 'groups')), 180) or 'node'}
            row.update({k: text(v) if isinstance(v, str) else v for k, v in fields.items()})
            if 'http' not in row and 'http_status' in row:row['http']=row['http_status']
            if 'exit' not in row and 'exit_code' in row:row['exit']=row['exit_code']
            if 'elapsed_ms' not in row and isinstance(row.get('total_seconds'),(int,float)):row['elapsed_ms']=round(row['total_seconds']*1000)
            if row.get('ok') is False and not row.get('error_detail') and not row.get('error'):
                row['error_detail'] = 'HTTP status rejected' if row.get('http') else 'Check failed; probe supplied no error text'
            rows.append(row)
        for key, child in value.items():
            if key in ('metrics', 'credentials', 'config', 'settings', 'diagnostics'):
                continue
            if isinstance(child, dict):
                visit(child, path+(str(key),), depth+1)
            elif isinstance(child, list) and key in ('checks', 'routes', 'certificates'):
                for i, item in enumerate(child[:80]):
                    visit(item, path+(str(key), str(i)), depth+1)
    if isinstance(result.get('diagnostics'), list):
        for row in result['diagnostics'][:200]:
            if isinstance(row, dict):
                rows.append({k: text(v, 180 if k=='check' else 1024) if isinstance(v, str) else v
                             for k,v in row.items() if k in FIELDS+('check',) and isinstance(v,(str,int,float,bool,type(None)))})
    else:
        visit(result.get('report', result))
    existing = {r.get('check') for r in rows}
    for label in result.get('failures', [])[:80]:
        if str(label) not in existing:
            rows.append({'check':text(label,180),'ok':False,'error_detail':'Failure label supplied without a matching detailed probe'})
    rows.sort(key=lambda r: r.get('ok') is not False and not r.get('error') and not r.get('exit'))
    kept=[];size=0
    for row in rows:
        n=len(json.dumps(row,ensure_ascii=False).encode())
        if size+n>32000 or len(kept)>=128:break
        kept.append(row);size+=n
    return kept

def format_failure(row):
    bits=[str(row.get('check','node'))]
    for field,label in [('exit','exit'),('http','HTTP'),('elapsed_ms','мс')]:
        if row.get(field) is not None:bits.append(label+'='+str(row[field]))
    error=row.get('error_detail') or row.get('error') or row.get('reason')
    if error:bits.append(text(error,220).replace('\n',' '))
    return '; '.join(bits)
