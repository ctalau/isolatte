# TeaVM + Saxon-HE XSLT execution in Node

This experiment compiles **Saxon-HE 12.10** and **Xerces-J 2.12.2** with **TeaVM 0.16.0**, then compiles and executes supplied XSLT stylesheets in Node. Java is needed at build time only. The runtime does not launch a JVM and does not use SaxonJS or a host XSLT engine.

**Result:** the adapted JavaScript build runs the sample XSLT 3.0 transformation. The test suite checks text/XML/JSON serialization, templates and numeric sorting, grouping, maps/arrays, Unicode regex, normalization, decimal arithmetic, and error/resource-rejection behavior. See [verification](results/verification.txt), [JVM sample reference](results/jvm-reference.txt), and [initial compiler failures](results/baseline-build.txt).

The initial Saxon build, already using the earlier Xerces adaptation, failed with 70 missing-API diagnostics. This working version deliberately narrows the available platform features; it is a feasibility port, not a general Saxon distribution or production sandbox.

## Run

Requirements: JDK 21, Maven 3.9+, Node 18+. Measured with Corretto 21.0.12.1, Maven 3.9.9 and Node 24.19.0. Each experiment is self-contained; this folder does not require the separate Xerces experiment.

```sh
cd teavm-node-saxon
mvn -B clean package
node run.mjs
node run.mjs /path/to/stylesheet.xsl /path/to/input.xml
node verify.mjs
```

The sample prints:

```text
CAFÉ & XML | TEAVM
Total: 20.00
```

Node reads both files as strict UTF-8. The compiled Java method constructs Saxon's processor, compiles the supplied stylesheet, transforms the supplied XML, and returns the serialized result as a string. The runner writes that string exactly, including outputs without a final newline. Errors exit with status 1. No output file is written by default.

## Compare with JVM Saxon

The optional reference runner intentionally launches Java. It runs the same Java entry point against the original dependencies, without applying TeaVM's bytecode transformers.

```sh
mvn -B org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath \
  -Dmdep.outputFile=target/classpath.txt
node reference.mjs
node verify.mjs --jvm
```

`JAVA_HOME`, when set, selects the reference JDK. The suite compares every successful transformation's output byte-for-byte with JVM Saxon, as well as with a stated expected output. Negative tests require a nonzero exit, empty stdout and the expected diagnostic.

Run `node benchmark.mjs` after building the classpath to compare fresh-process latency and repeated transformations with and without a cached stylesheet. In the measured workloads, TeaVM/Node took **1.5–5.7× longer per repeated transformation** than the JVM. See [performance results and methodology](PERFORMANCE.md) and [raw measurements](results/benchmark.json).

## Adaptations

Downloaded JARs remain unchanged. TeaVM's build-time class transformers alter the reachable bytecode, with the following explicit replacements:

| Area | Adaptation |
| --- | --- |
| XML parsing | Explicit nonvalidating Xerces configuration and datatype factory; exception superclass/catch adaptation; diagnostic bundle registration |
| Parser pools | Replace `ConcurrentLinkedQueue` with `ArrayDeque` on the single Node thread |
| Stylesheet checksums | Replace `DigestMaker` with a Node SHA-256 bridge |
| Unicode normalization | Map Java's normalizer and form enum to ECMAScript `String.normalize()` |
| Saxon regex tables | Embed case variants, categories, Unicode blocks and entities; open them through TeaVM resource streams |
| Additional reachable helpers | Fixed-offset time zone and `readLine()`/line-number reader adapters |
| Dynamic loading | Construct `Configuration` directly; reject dynamic class loading and reflective configuration/trace-listener creation |
| Catalogs and optional Java features | Disable catalog initialization; reject catalog operations, Java locale/UCA collations, DOM result construction, and unsupported external collection/binary helpers |
| Environment | Expose no environment variables; supply a synthetic `user.dir` only when missing, for Xerces' resource URI expansion |
| TeaVM console | Fix the pinned 0.16.0 implementation's clear-before-invoke flush callback bug, so Saxon diagnostics reach stderr |

`TransformXml` also rejects resource requests, unparsed-text reads, collections and secondary result documents. Xerces rejects DOCTYPE declarations in both inputs. These are tested configuration restrictions, not a complete audit of every Saxon extension or possible host call.

## Limits and next steps

The generated **nonminified** CommonJS module is about 40 MB. Inputs, trees, checksum data and serialized output reside in memory. The runner has no execution-time or memory budget; the verification harness imposes subprocess timeouts only.

Java locale collations, external includes/imports/documents, text/collection reads, secondary outputs, reflective extensions, catalog operations and DOM destinations are unavailable in this configuration. The default Saxon codepoint collation remains available. Broader time-zone and line-reader behavior, package import/export, schema-aware processing, other encodings, browser execution and the Wasm GC backend have not been established. This suite does not establish complete XSLT 3.0 conformance.

**Assessment:** compiling Saxon and executing supplied XSLT through TeaVM is feasible for the tested in-memory flow. A general-purpose port would need a larger compatibility layer and a representative conformance corpus. Next I would run real project stylesheets, assess the missing capabilities they require, and measure a minified build before investigating Wasm GC or browser hosting.

References: [Saxon 12.10 release](https://blog.saxonica.com/announcements/2026/07/saxon-12.10.html), [Saxon s9api XSLT compiler](https://www.saxonica.com/html/documentation12/javadoc/net/sf/saxon/s9api/XsltCompiler.html), [TeaVM Maven configuration](https://teavm.org/docs/tooling/maven.html).
