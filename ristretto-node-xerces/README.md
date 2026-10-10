# Ristretto + Xerces-J and Saxon HE inside Node

This experiment runs the Rust Ristretto JVM as WASM inside Node, loads external Xerces-J and Saxon HE JARs, and parses/transforms XML using Java `FileInputStream`. No Java subprocess is launched at runtime.

**Result:** Xerces parsing and Saxon HE XSLT 2.0 transformation work inside Node. UTF-8, namespaces, entities, malformed-input errors and missing files work. Explicit host capabilities deny writes and HTTP. Java probes confirm host files/environment are hidden. Class loading still shares a filesystem with Java I/O; execution and memory limits are missing. This is a feasibility PoC, not a production sandbox.

See [SANDBOX.md](SANDBOX.md) for architecture, class loading, capabilities, required WASI operations, memory measurements and a proposed QuickJS-style design. Evidence:

- [Measured report](results/sandbox-report.json)
- [Verification output](results/verification.txt)
- [Initial PoC result](results/original-poc.json)
- [Saxon HE transform result](results/saxon-poc.json)
- [Saxon HE verification output](results/saxon-verification.txt)

## Reproduce

Requirements: Linux x64, Node 24+, Git, curl, tar, sha256sum, Rust/rustup. Input containment uses Linux `/proc/self/fd`.

```sh
cd ristretto-node-xerces
rustup toolchain install 1.99.0 --profile minimal --target wasm32-wasip2
bash setup.sh
npm run build
npm run verify
npm run verify:saxon
npm run transform
npm run inspect
npm start
node run.mjs /absolute/path/to/your.xml
```

Setup clones pinned Ristretto into `vendor/ristretto`, verifies JDK/JAR SHA-256 hashes, creates an uncompressed `java.base,java.xml` runtime image, and installs locked npm dependencies. Building uses javac and Cargo; jco converts the component to JS bindings/core WASM. Build/download tools have normal host privileges; runtime controls apply only to the guest. Large dependencies and generated binaries are excluded from Git.

Pinned versions:

- Ristretto 0.34.0, commit `dcd45fb452d6956122a9985096260310a22b4d44`.
- Rust 1.99.0; the dependency build uses `RUSTC_BOOTSTRAP=1`.
- Corretto distribution 21.0.12.12.1; guest Java 21.0.12.1.
- Xerces-J 2.12.2, xml-apis 1.4.01, Saxon HE 10.9.
- jco-transpile 0.12.1, preview2-shim 0.23.0; measured on Node 24.19.0.

## Saxon HE proof of concept

```sh
npm run transform
node transform.mjs /absolute/path/to/input.xml /absolute/path/to/stylesheet.xsl
npm run verify:saxon
```

Both files must be directly inside the same authorized input directory. Node copies them into the read-only memory filesystem as `/input/document.xml` and `/input/stylesheet.xsl`. The WIT `transform` export creates a fresh Ristretto JVM, calls `TransformXml.transform`, compiles the stylesheet with the explicit `net.sf.saxon.TransformerFactoryImpl`, and returns the serialized result as a string. No Java executable is used at runtime.

The bundled stylesheet transforms `sample.xml` with namespace matching, sorting and the XSLT 2.0 `upper-case()` function:

```text
b1: RISTRETTO & XERCES — CAFÉ
b2: NODE.JS JVM
```

Saxon HE 10.9 is deliberately pinned: it is a self-contained Java 8-compatible JAR without an additional XML resolver dependency. Setup verifies its SHA-256 alongside Xerces and the JDK. The recorded cold sample transform took about 15 seconds on this workspace; this is an observation, not a benchmark. This proves the pinned version/workload, not compatibility with newer Saxon releases.

Saxon stylesheet compilation initializes Java date/time support, so the memory host also mounts the JDK `lib/tzdb.dat` resource. The original Xerces workload did not need it.

Both XML and XSLT use Xerces SAX parsers with DOCTYPE/external entities disabled. Additional URI resources (`xsl:include`, `xsl:import`, `document()`) and `unparsed-text()` are denied; external functions are disabled. The host still denies filesystem writes and HTTP. Stylesheets use the fixed guest filenames as base URIs; multi-file stylesheets are outside this PoC. Treat stylesheets as trusted: this is not an arbitrary XSLT sandbox. The input quota applies to each file; returned transformation strings and Java heap are not bounded by the stdout/stderr quota. Deadlines and memory limits remain unimplemented.

## Implementation

| File | Purpose |
| --- | --- |
| `src/lib.rs`, `wit/world.wit` | `parse(path)`/`transform(xml-path, xslt-path)`/`probe()` exports; fresh interpreted JVM per call |
| `java/ParseXml.java` | External Xerces DOM; DTDs/external entities disabled |
| `java/TransformXml.java` | Saxon HE JAXP bridge; Xerces SAX sources, serialized result returned to Node |
| `transform.mjs`, `sample.xsl`, `verify-saxon.mjs` | XSLT CLI, XSLT 2.0 sample and regression checks |
| `java/ProbeSandbox.java` | Java I/O, NIO, environment, subprocess and library probes |
| `host.mjs` | Selected XML/XSLT/runtime copied into memory filesystem; input/output budgets |
| `host-policy.mjs` | Explicit imports, read-only enforcement, HTTP denial, call audit |
| `host-disk.mjs` | Diagnostic real-disk comparison; **not the restricted host** |
| `verify.mjs`, `inspect.mjs` | Functional/capability checks and size/import/call measurements |

`parse` and `transform` synchronously block their Node thread. The JVM is fresh per call, but component/shim state persists. The shim uses module globals: independent tenants need independent workers/realms. Concurrent tenants, arbitrary bytecode, schema validation, infinite loops and memory exhaustion have not been tested.

Initial Java 8 failed: Ristretto's native ZIP reader returned decompressed bytes where Java expected compressed bytes. Java 21 works without upstream changes. Initial cold runs took about 8–9 seconds with memory files and 134 seconds with disk mounts, whose many tiny JImage reads cross an I/O worker boundary. These are observations, not a benchmark.

Diagnostic comparison: `node run.mjs --disk sample.xml`. This mounts real directories, including the experiment directory, and lacks the memory host's read-only policy. Do not use it for untrusted bytecode.

## Assessment

The Node/Xerces parsing and Saxon HE transformation demonstrations work and support a restricted Java sandbox design. It lacks separate artifact loading, instruction interruption and memory limits. Next: implement those controls and audit every host operation before testing hostile bytecode/XML.
