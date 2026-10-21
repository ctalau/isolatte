import json,collections,datetime,re
d=json.load(open('samples2.json'))['recording']['events']
N=len(d)
def ts(s): return datetime.datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()
t0=min(ts(e['values']['startTime']) for e in d)
ph=[(float(m.group(1)),m.group(2)) for l in open('phases.txt') for m in [re.match(r'\s*([\d.]+) ==> (.*)',l)] if m]
ph.append((66.14,'END'))
def fn(f): return f['method']['type']['name'].replace('/','.')+'.'+f['method']['name']
def owner(n):
    if n.startswith('org.dita.dost.util.Job.getFileInfo') or n.startswith('org.dita.dost.util.Job.lambda$getFileInfo') or n.startswith('org.dita.dost.util.Job$$Lambda'): return 'getFileInfo scan'
    if n.startswith('org.ditang.relaxng') or n.startswith('org.apache.xerces'): return 'Xerces+RNG parse'
    if n.startswith('net.sf.saxon.regex') or '.REMatcher' in n: return 'Saxon regex'
    if n.startswith('net.sf.saxon.serialize') or n.startswith('net.sf.saxon.event'): return 'Saxon serialize'
    if n.startswith('net.sf.saxon'): return 'Saxon transform'
    if n.startswith('org.dita.dost'): return 'DITA-OT Java'
    return None
cnt=collections.defaultdict(collections.Counter); tot=collections.Counter()
allc=collections.Counter()
for e in d:
    t=ts(e['values']['startTime'])-t0+0.5
    names=[fn(f) for f in e['values']['stackTrace']['frames']]
    o=next((owner(n) for n in names if owner(n)),'JDK/other')
    p='startup/JVM' if t<ph[0][0] else next((ph[i][1] for i in range(len(ph)-1) if ph[i][0]<=t<ph[i+1][0]),'END')
    cnt[p][o]+=1; tot[p]+=1; allc[o]+=1
print("OVERALL"); 
for k,v in allc.most_common(): print(f"  {100*v/N:5.1f}% {k}")
print()
for i in range(len(ph)-1):
    n=ph[i][1]; wall=ph[i+1][0]-ph[i][0]
    if wall<0.5: continue
    c=tot[n]
    print(f"{wall:5.1f}s {100*wall/66.14:4.1f}%  {n[:55]:55s} "+" ".join(f"{k}:{round(100*v/max(c,1))}" for k,v in cnt[n].most_common(4)))
