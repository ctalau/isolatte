import json,sys,collections,re
d=json.load(open('samples2.json'))['recording']['events']
N=len(d)
def fn(f): return f['method']['type']['name'].replace('/','.')+'.'+f['method']['name']
def owner(n):
    if n.startswith('org.dita.dost.util.Job.getFileInfo') or n.startswith('org.dita.dost.util.Job.lambda$getFileInfo'): return 'Job.getFileInfo scan'
    if n.startswith('org.ditang.relaxng'): return 'RelaxNG-defaults component (ditang)'
    if n.startswith('net.sf.saxon'): return 'Saxon (XSLT/tree/serialize)'
    if n.startswith('org.apache.xerces'): return 'Xerces scanner/DTD/NS'
    if n.startswith('org.dita.dost'): return n.rsplit('.',1)[0].replace('org.dita.dost.','dita.')
    if n.startswith('org.apache.tools.ant'): return 'ant'
    return None
own=collections.Counter(); leafjdk=collections.defaultdict(collections.Counter)
getfi_lines=collections.Counter(); getfi_fromleaf=collections.Counter()
for e in d:
    names=[fn(f) for f in e['values']['stackTrace']['frames']]
    o=next((owner(n) for n in names if owner(n)),'jdk/other')
    own[o]+=1
    if o=='Job.getFileInfo scan': getfi_fromleaf[names[0]]+=1
print("EXCLUSIVE OWNER (leaf-up)")
for k,v in own.most_common(25): print(f"{100*v/N:5.1f} {k}")
print("\ngetFileInfo leaf frames")
for k,v in getfi_fromleaf.most_common(8): print(f"{100*v/N:5.1f} {k}")
# inclusive of key entry points
inc=collections.Counter()
keys=['Job.getFileInfo','RelaxDefaultsParserConfiguration.parse','XsltModule.transform','StreamStore.transformUri','StreamStore.writeDocument','AbstractReaderModule.readFile','net.sf.saxon.s9api.Xslt30Transformer','XMLUtils.getXMLReader','TransformerFactory','Serializer','MoveMetaModule','KeyrefModule','ChunkModule','MoveLinksModule','CleanPreprocessModule','DebugFilter','ProfilingFilter','TopicFragmentFilter','DitaWriterFilter','ConrefPushModule','org.dita.dost.module.reader.TopicReaderModule','DitaClass.getInstance','StringUtils','URLUtils']
for e in d:
    names=[fn(f) for f in e['values']['stackTrace']['frames']]
    for k in keys:
        if any(k in n for n in names): inc[k]+=1
print("\nINCLUSIVE")
for k,v in inc.most_common(): print(f"{100*v/N:5.1f} {k}")
