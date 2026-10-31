"""Turn a Markdown docs checkout into one XML 'facts' document for Schematron.

Python only parses Markdown and normalises relative paths; every pass/fail
decision is made by the Schematron rules in rules.sch.
usage: python3 -I extract.py REPO_DIR COMMIT OUT.xml [DOCSET_ROOT]
DOCSET_ROOT is what "~/" means in DocFX paths (sql-docs: docs; azure-docs: repo root).
"""
import glob, json, os, re, subprocess, sys
from xml.sax.saxutils import quoteattr, escape

repo, commit, out = sys.argv[1:4]
root = sys.argv[4] if len(sys.argv) > 4 else ''
deps = set()
cfg = os.path.join(repo, '.openpublishing.publish.config.json')
if os.path.exists(cfg):
    _c = json.load(open(cfg, encoding='utf-8'))
    deps = {d.get('path_to_root') for d in _c.get('dependent_repositories', [])}
    docsets = sorted({d.get('build_source_folder', '.').strip('./') for d in _c.get('docsets_to_publish', [])}, key=len, reverse=True)
else:
    docsets = []

def docset_root(p):
    for d in docsets:
        if d and (p + '/').startswith(d + '/'):
            return d
    return root
tree = subprocess.run(['git', '-C', repo, 'ls-tree', '-r', '--name-only', commit],
                      capture_output=True, text=True, check=True).stdout.split('\n')
tree = [t for t in tree if t]
mds = [t for t in tree if t.lower().endswith('.md')]

FM = re.compile(r'\A---\s*\n(.*?)\n---\s*\n', re.S)
INC = re.compile(r'\[!INCLUDE\s*\[[^\]]*\]\(([^)\s]+)\)', re.I)
LINK = re.compile(r'(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
IMG = re.compile(r'!\[([^\]]*)\]\(([^)\s]+)[^)]*\)')
TRIPLE_IMG = re.compile(r':::image\s+([^\n]*?):::')
ATTR = re.compile(r'([\w-]+)="([^"]*)"')
ZONE = re.compile(r'^:::\s*zone\s+pivot="([^"]*)"', re.M)
HEAD = re.compile(r'^(#{1,6})\s')
FENCE = re.compile(r'^(\s*)(```+|~~~+)\s*([^\s`]*)')
ANCHOR = re.compile(r'<a name="([^"]+)"></a>')
TERMS = {
    'Azure Active Directory': re.compile(r'\bAzure Active Directory\b'),
    'Azure AD': re.compile(r'\bAzure AD\b(?! B2C)'),
    'SQL Data Warehouse': re.compile(r'\bSQL Data Warehouse\b'),
    'Amazon Elasticsearch Service': re.compile(r'\bAmazon Elasticsearch Service\b'),
}

def norm(base, target):  # noqa: C901
    """Repo-relative path, 'XREPO:<path>' for a dependent repository, or None for URLs."""
    target = target.split('#')[0].split('?')[0].replace('\\', '/')
    if target.startswith('~/'):
        r = os.path.normpath(os.path.join(docset_root(base), target[2:])).replace(os.sep, '/')
        if r.split('/')[0] in deps:
            return 'XREPO:' + r
        return r
    if not target or re.match(r'^[a-z][a-z0-9+.-]*:', target, re.I) or target.startswith('/'):
        return None
    return os.path.normpath(os.path.join(os.path.dirname(base), target)).replace(os.sep, '/')

w = open(out, 'w', encoding='utf-8')
w.write('<corpus repo=%s commit=%s>\n<files>\n' % (quoteattr(os.path.basename(repo)), quoteattr(commit)))
for t in tree:
    w.write('<f p=%s/>\n' % quoteattr(t))
w.write('</files>\n')
w.write('<redirects>\n')
for rf in glob.glob(os.path.join(repo, '**', '.openpublishing.redirection*.json'), recursive=True):
    try:
        for e in json.load(open(rf, encoding='utf-8-sig')).get('redirections', []):
            w.write('<redir p=%s/>\n' % quoteattr((e.get('source_path') or e.get('source_path_from_root') or '').lstrip('/')))
    except ValueError:
        pass
w.write('</redirects>\n')
pgs = [t for t in tree if t.endswith('zone-pivot-groups.yml')]
if pgs:
    w.write('<pivotgroups>\n')
grp = None
for pg in pgs:
    for line in open(os.path.join(repo, pg), encoding='utf-8'):
        m = re.match(r'^- id:\s*(\S+)', line)
        if m:
            grp = m.group(1); w.write('<pivot g=%s id=""/>\n' % quoteattr(grp)); continue
        m = re.match(r'^\s+- id:\s*(\S+)', line)
        if m and grp:
            w.write('<pivot g=%s id=%s/>\n' % (quoteattr(grp), quoteattr(m.group(1))))
if pgs:
    w.write('</pivotgroups>\n')
for p in mds:
    fp = os.path.join(repo, p)
    if not os.path.isfile(fp):
        continue
    text = open(fp, encoding='utf-8', errors='replace').read()
    w.write('<doc p=%s inc=%s>\n' % (quoteattr(p), quoteattr('yes' if '/includes/' in '/' + p else 'no')))
    m = FM.match(text)
    body = text
    if m:
        body = text[m.end():]
        for line in m.group(1).split('\n'):
            mm = re.match(r'^([\w.\-]+):\s*(.*?)\s*$', line)
            if mm:
                k, v = mm.group(1), re.sub(r'\s+#.*$', '', mm.group(2)).strip().strip('"\'').strip()
                if k == 'ms.date':
                    d = re.match(r'(\d{1,2})/(\d{1,2})/(\d{4})', v)
                    if d:
                        v = '%s%02d%02d' % (d.group(3), int(d.group(1)), int(d.group(2)))
                w.write('<meta k=%s v=%s/>\n' % (quoteattr(k), quoteattr(v)))
    prose = re.sub(r'^\s*(```+|~~~+).*?^\s*\1\s*$', '', body, flags=re.M | re.S)
    prose = re.sub(r'`[^`\n]*`', '', prose)
    for t in INC.findall(body):
        w.write('<include href=%s r=%s/>\n' % (quoteattr(t), quoteattr(norm(p, t) or '')))
    for t in LINK.findall(prose):
        r = norm(p, t)
        if r is not None:
            w.write('<link href=%s r=%s/>\n' % (quoteattr(t), quoteattr(r)))
        elif re.match(r'https?://docs\.aws\.amazon\.com/', t):
            w.write('<extlink host="docs.aws.amazon.com" href=%s/>\n' % quoteattr(t))
    for alt, t in IMG.findall(prose):
        w.write('<img alt=%s href=%s r=%s/>\n' % (quoteattr(alt.strip()), quoteattr(t), quoteattr(norm(p, t) or '')))
    for attrs in TRIPLE_IMG.findall(prose):
        a = dict(ATTR.findall(attrs))
        if a.get('type') == 'icon':
            continue
        t = a.get('source', '').strip()
        w.write('<img alt=%s href=%s r=%s/>\n' % (quoteattr(a.get('alt-text', '').strip()), quoteattr(t), quoteattr(norm(p, t) or '')))
    for z in ZONE.findall(body):
        for pid in z.split(','):
            w.write('<zone pivot=%s/>\n' % quoteattr(pid.strip()))
    infence = False
    prev = 0
    for line in body.split('\n'):
        f = FENCE.match(line)
        if f:
            if not infence:
                w.write('<code lang=%s/>\n' % quoteattr(f.group(3)))
            infence = not infence
            continue
        if infence:
            continue
        h = HEAD.match(line)
        if h:
            lvl = len(h.group(1))
            w.write('<h l="%d" prev="%d"/>\n' % (lvl, prev))
            prev = lvl
        for a in ANCHOR.findall(line):
            w.write('<anchor id=%s/>\n' % quoteattr(a))
        for term, rx in TERMS.items():
            for _ in rx.findall(line):
                w.write('<term t=%s/>\n' % quoteattr(term))
    w.write('</doc>\n')
w.write('</corpus>\n')
w.close()
