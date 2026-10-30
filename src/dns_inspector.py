"""Read-only public DNS and conservative SPF diagnostics. Uses dig without a shell."""
import ipaddress
import re
import subprocess

class DNSError(Exception):pass

DOMAIN = re.compile(r'^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$')

# RFC 6761, RFC 6762, RFC 8375 and ICANN's reserved .internal domain.
# These are not public sender domains and must never be queried by this tool.
NON_PUBLIC_TLDS = frozenset({'localhost', 'local', 'test', 'invalid', 'example', 'internal'})
NON_PUBLIC_ARPA = ('home.arpa', 'in-addr.arpa', 'ip6.arpa')

def public_dns_domain(name):
    if not isinstance(name, str) or not DOMAIN.fullmatch(name):
        return False
    if name.rsplit('.', 1)[-1] in NON_PUBLIC_TLDS:
        return False
    return not any(name == suffix or name.endswith('.' + suffix) for suffix in NON_PUBLIC_ARPA)

def lookup(domain, rrtype='TXT'):
    # Only approved service labels atop an ordinary, public DNS domain are allowed.
    acceptable = public_dns_domain(domain)
    if isinstance(domain, str):
        for prefix in ('_rsm.', '_dmarc.'):
            if domain.startswith(prefix) and public_dns_domain(domain[len(prefix):]):
                acceptable = True
        m = re.fullmatch(r'([a-z0-9_-]{1,63})\._domainkey\.(.+)', domain)
        if m and public_dns_domain(m.group(2)):
            acceptable = True
    if not acceptable or rrtype not in ('TXT','A','AAAA','MX'):
        raise DNSError('Invalid DNS query')
    try:
        p=subprocess.run(['/usr/bin/dig','+short','+time=2','+tries=1',domain,rrtype],
                         capture_output=True,text=True,timeout=7,check=True)
    except (OSError,subprocess.SubprocessError) as e:
        raise DNSError('DNS resolver unavailable: '+str(e)[:160])
    if len(p.stdout)>16384:raise DNSError('DNS response too large')
    if rrtype!='TXT':return [s.strip() for s in p.stdout.splitlines() if s.strip()]
    result=[]
    for line in p.stdout.splitlines():
        # dig quotes individual TXT string chunks; concatenate within a single RR.
        segments=re.findall(r'"((?:\\.|[^"\\])*)"',line)
        if segments:
            result.append(''.join(re.sub(r'\\([0-9]{3})',lambda m:chr(int(m.group(1))),s).replace('\\"','"') for s in segments))
    return result

def get_spf(domain):
    return [x for x in lookup(domain) if x.lower().startswith('v=spf1') and (len(x)==6 or x[6].isspace())]

def mechanisms(record):
    return record.split()[1:]

def lookup_cost(record):
    items=mechanisms(record)
    count=0
    for item in items:
        token=item.lstrip('+-~?').lower()
        if token=='a' or token.startswith(('a:','a/','mx:','mx/','include:','exists:','ptr','redirect=')) or token=='mx':
            count+=1
    return count

def suggested_spf(record, ip):
    """Returns (candidate or None, status). No policy-changing rewrites."""
    if not ip:return None,'Enter the verified actual outbound MTA IP to evaluate a change.'
    ipobj=ipaddress.ip_address(ip)
    part=('ip4:' if ipobj.version==4 else 'ip6:')+str(ipobj)
    tokens=record.split()
    if not tokens or tokens[0].lower()!='v=spf1':return None,'Malformed SPF.'
    if any('redirect=' in x.lower() for x in tokens):
        return None,'SPF uses redirect=; manual review required; no automatic proposal.'
    if any('%{' in x for x in tokens):return None,'Macros in SPF: manual review required.'
    for t in tokens[1:]:
        z=t.lstrip('+-~?')
        if z.lower().startswith(('ip4:','ip6:')):
            try:
                net=ipaddress.ip_network(z.split(':',1)[1],strict=False)
                if ipobj in net and (t[0] not in '-~?' ):
                    return record,'IP is already explicitly permitted by an ip4/ip6 mechanism.'
            except ValueError:pass
    all_indices=[i for i,t in enumerate(tokens) if t.lstrip('+-~?').lower()=='all']
    idx=all_indices[0] if all_indices else len(tokens)
    tokens.insert(idx,part)
    return ' '.join(tokens),'Candidate only: DNS-based effective authorization and DMARC alignment must be validated before publishing.'

def diagnostics(domain,ip='',selector=''):
    spf=get_spf(domain)
    result={'domain':domain,'spf_records':spf,'ip':ip,'suggested':None,'warnings':[],
            'lookup_cost_minimum':None,'dmarc':[], 'dkim':'Selector and signed sample needed; cannot infer DKIM signing from DNS alone',
            'alignment':'Unknown without real envelope/header/signature sample', 'dkim_selector':selector, 'dkim_dns':[],'dmarc_policy':'unknown'}
    if not spf:
        result['warnings'].append('No SPF record. Do not publish guessed policies.')
    elif len(spf)>1:
        result['warnings'].append('Multiple SPF records: SPF PermError. Must fix manually.')
    else:
        rec=spf[0]
        result['lookup_cost_minimum']=lookup_cost(rec)
        if result['lookup_cost_minimum']>10:result['warnings'].append('SPF apparent DNS lookup count exceeds 10 (PermError).')
        if re.search(r'\b(?:include|redirect)=?[^\s]*',rec):
            result['warnings'].append('Includes/redirects may add nested DNS lookups; not fully evaluated here.')
        result['suggested'],message=suggested_spf(rec,ip)
        result['warnings'].append(message)
        if ip and result['suggested']!=rec:
            result['warnings'].append('IP authorization by existing a/mx/include/redirect was not evaluated: candidate may be unnecessary.')
    if selector:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,63}',selector):raise DNSError('Invalid DKIM selector')
        result['dkim_dns']=[v for v in lookup(selector+'._domainkey.'+domain) if 'v=DKIM1' in v or 'p=' in v]
        result['dkim']='Selector TXT found; live DKIM signature still unverified' if result['dkim_dns'] else 'No public TXT at this selector; other selectors may exist'
    try:
        result['dmarc']=lookup('_dmarc.'+domain)
        result['dmarc']=[v for v in result['dmarc'] if v.lower().startswith('v=dmarc1')]
        if len(result['dmarc'])>1:result['warnings'].append('Multiple DMARC records may invalidate DMARC.')
        if len(result['dmarc'])==1:
            tags=dict((k.lower(),v) for k,v in re.findall(r'(?:^|;)\s*([a-zA-Z]+)\s*=\s*([^;\s]+)',result['dmarc'][0]))
            result['dmarc_policy']=tags.get('p','missing')
            if result['dmarc_policy'] not in ('none','quarantine','reject'):
                result['warnings'].append('DMARC p policy missing or invalid')
    except DNSError as e: result['warnings'].append(str(e))
    return result
