# Ristretto + Xerces-J inside Node

This experiment runs the Rust Ristretto JVM as WASM inside Node, loads the external Xerces-J JAR, and parses XML using Java `FileInputStream`. No Java subprocess is launched at runtime.

**Result:** UTF-8, namespaces, entities, malformed-input errors and missing files work. Explicit host capabilities deny writes and HTTP. Java probes confirm host files/environment are hidden. Class loading still shares a filesystem with Java I/O; execution and memory limits are missing. This is a feasibility PoC, not a production sandbox.

See [SANDBOX.md](SANDBOX.md) for architecture, class loading, capabilities, required WASI operations, memory measurements and a proposed QuickJS-style design. Evidence:

- [Measured report](results/sandbox-report.json)
- [Verification output](results/verification.txt)
- [Initial PoC result](results/original-poc.json)

## Reproduce

Requirements: Linux x64, Node 24+, Git, curl, tar, sha256sum, Rust/rustup. Input containment uses Linux `/proc/self/fd`.

```sh
cd ristretto-node-xerces
rustup toolchain install 1.99.0 --profile minimal --target wasm32-wasip2
bash setup.sh
npm run build
npm run verify
npm run inspect
npm start
node run.mjs /absolute/path/to/your.xml
```

Setup clones pinned Ristretto into `vendor/ristretto`, verifies JDK/JAR SHA-256 hashes, creates an uncompressed `java.base,java.xml` runtime image, and installs locked npm dependencies. Building uses javac and Cargo; jco converts the component to JS bindings/core WASM. Build/download tools have normal host privileges; runtime controls apply only to the guest. Large dependencies and generated binaries are excluded from Git.

Pinned versions:

- Ristretto 0.34.0, commit `dcd45fb452d6956122a9985096260310a22b4d44`.
- Rust 1.99.0; the dependency build uses `RUSTC_BOOTSTRAP=1`.
- Corretto distribution 21.0.12.12.1; guest Java 21.0.12.1.
- Xerces-J 2.12.2, xml-apis 1.4.01.
- jco-transpile 0.12.1, preview2-shim 0.23.0; measured on Node 24.19.0.

## Implementation

| File | Purpose |
| --- | --- |
| `src/lib.rs`, `wit/world.wit` | `parse(path)`/`probe()` exports; fresh interpreted JVM per call |
| `java/ParseXml.java` | External Xerces DOM; DTDs/external entities disabled |
| `java/ProbeSandbox.java` | Java I/O, NIO, environment, subprocess and library probes |
| `host.mjs` | Selected XML/runtime copied into memory filesystem; input/output budgets |
| `host-policy.mjs` | Explicit imports, read-only enforcement, HTTP denial, call audit |
| `host-disk.mjs` | Diagnostic real-disk comparison; **not the restricted host** |
| `verify.mjs`, `inspect.mjs` | Functional/capability checks and size/import/call measurements |

`parse` synchronously blocks its Node thread. The JVM is fresh per call, but component/shim state persists. The shim uses module globals: independent tenants need independent workers/realms. Concurrent tenants, arbitrary bytecode, schema validation, infinite loops and memory exhaustion have not been tested.

Initial Java 8 failed: Ristretto's native ZIP reader returned decompressed bytes where Java expected compressed bytes. Java 21 works without upstream changes. Initial cold runs took about 8–9 seconds with memory files and 134 seconds with disk mounts, whose many tiny JImage reads cross an I/O worker boundary. These are observations, not a benchmark.

Diagnostic comparison: `node run.mjs --disk sample.xml`. This mounts real directories, including the experiment directory, and lacks the memory host's read-only policy. Do not use it for untrusted bytecode.

## Assessment

The Node/XML demonstration works and supports a restricted Java sandbox design. It lacks separate artifact loading, instruction interruption and memory limits. Next: implement those controls and audit every host operation before testing hostile bytecode/XML.
