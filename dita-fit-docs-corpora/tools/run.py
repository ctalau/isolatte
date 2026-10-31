"""Validate a facts XML against rules.sch with lxml's ISO Schematron; print counts per rule.
usage: python3 -I run.py rules.sch facts.xml [svrl_out.xml]"""
import sys, collections, time
from lxml import etree, isoschematron
sch = isoschematron.Schematron(etree.parse(sys.argv[1]), store_report=True)
t = time.time(); doc = etree.parse(sys.argv[2]); valid = sch.validate(doc); dt = time.time() - t
rep = sch.validation_report
ns = {'svrl': 'http://purl.oclc.org/dsdl/svrl'}
c = collections.Counter(); files = collections.defaultdict(set); samples = collections.defaultdict(list)
for e in rep.xpath('//svrl:failed-assert|//svrl:successful-report', namespaces=ns):
    rid = e.get('id'); c[rid] += 1
    loc = e.get('location', '')
    m = __import__('re').search(r'doc\[(\d+)\]', loc)
    if m: files[rid].add(m.group(1))
    if c[rid] <= 2: samples[rid].append(' '.join(e.xpath('string(svrl:text)', namespaces=ns).split()))
for k in sorted(c): print(f'{k}\t{c[k]}\tfiles={len(files[k])}\t' + ' | '.join(samples[k]))
print(f'docs\t{len(doc.xpath("//doc"))}\tseconds\t{dt:.1f}')
if len(sys.argv) > 3: rep.write(sys.argv[3])
