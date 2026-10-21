import json,collections
d=json.load(open('samples2.json'))['recording']['events']; N=len(d)
def fn(f): return f['method']['type']['name'].replace('/','.')+'.'+f['method']['name']
c=collections.Counter(); leafs=collections.defaultdict(collections.Counter)
for e in d:
    names=[fn(f) for f in e['values']['stackTrace']['frames']]
    o=next((n for n in names if n.startswith(('org.apache.xerces','org.ditang','org.dita','net.sf.saxon'))),None)
    if not o or not o.startswith(('org.apache.xerces','org.ditang')): continue
    cls=o.rsplit('.',1)[0]
    if 'XMLDTDValidator' in cls: k='DTD validator (default attrs, validity)'
    elif 'XMLDTD' in cls or 'DTDGrammar' in cls: k='DTD declarations (grammar lookup/parse)'
    elif 'RelaxNG' in cls or 'ditang' in cls: k='RelaxNG-defaults component'
    elif 'XMLEntity' in cls: k='entity scanner / char decoding'
    elif 'XMLAttributes' in cls or 'QName' in cls or 'SymbolTable' in cls: k='attributes/QName/symbol table'
    else: k='scanner other: '+cls.split('.')[-1]
    c[k]+=1; leafs[k][o]+=1
tot=sum(c.values()); print("xerces-exclusive",f"{100*tot/N:.1f}%")
for k,v in c.most_common(8): print(f"  {100*v/N:5.1f}% {k}   top: {leafs[k].most_common(2)}")
