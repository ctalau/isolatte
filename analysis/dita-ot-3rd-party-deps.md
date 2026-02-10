# DITA-OT Third-Party Dependency Audit

**Project:** DITA Open Toolkit (dita-ot) v4.5.0-SNAPSHOT
**Source:** https://github.com/dita-ot/dita-ot
**Date:** 2026-02-10

## Summary

DITA-OT is a Java-based XML publishing toolkit that transforms DITA content into various output formats (HTML5, PDF, etc.). It relies on 13 runtime third-party dependencies and 6 test-only dependencies. The most deeply integrated libraries are Saxon (XSLT/XPath processing), Apache Ant (build orchestration), and Apache Xerces (XML parsing).

> **Note:** `com.idiominc.ws.opentopic` and `org.ditang.relaxng` are bundled source code within the DITA-OT project itself (in `src/main/plugins/` and `src/main/java/`), not external dependencies. They are excluded from this analysis.

---

## Runtime Dependencies by Sandboxing Priority

### HIGH Priority — Core Processing with File System and Network Access

These libraries directly perform file I/O, network access, or process execution and would benefit most from sandboxing.

| Dependency | Maven Coordinates | Version | Files (main/test) | Usage | Sandboxing Rationale |
|---|---|---|---|---|---|
| **Apache Ant** | `org.apache.ant:ant` | 1.10.15 | 44 / 12 | Build orchestration engine. DITA-OT's entire pipeline is built on Ant — tasks, targets, project execution, file operations, classpath management. Deeply embedded as the execution framework. | **HIGH** — Ant executes arbitrary tasks, spawns processes, performs file operations, and manages classpaths. A compromised Ant task could execute arbitrary code. |
| **Saxon-HE** | `net.sf.saxon:Saxon-HE` | 12.9 | 32 / 12 | XSLT 3.0 / XPath 3.1 processing engine. Used for all XML-to-output transformations (HTML5, PDF FO, etc.), XPath evaluation, XML serialization, extension functions, and collation. The single most critical processing library. | **HIGH** — Saxon processes user-supplied XSLT stylesheets which can use `xsl:result-document` (write files), Java extension functions (arbitrary code execution), and `doc()` / `unparsed-text()` (read files/URLs). XSLT is effectively a Turing-complete language. |
| **Apache Xerces** | `xerces:xercesImpl` | 2.12.2 | 8 / 2 | Low-level XML parsing with DTD/grammar support. Used for XML parsing configurations, DTD grammar caching, grammar pool management, XInclude processing, and entity resolution. | **HIGH** — XML parsers are a well-known attack surface (XXE, billion laughs, SSRF via entity resolution). Xerces handles DTD processing and external entity resolution. |
| **Apache Commons IO** | `commons-io:commons-io` | 2.19.0 | 18 / 10 | File utilities: copying, deleting, moving files; filename manipulation (extension, base name, normalization); stream management (IOUtils.closeQuietly). Pervasive file system utility. | **HIGH** — Direct file system manipulation (copy, delete, move). `FileUtils.deleteDirectory` is destructive. Path normalization bugs could lead to path traversal. |
| **XML Resolver** | `org.xmlresolver:xmlresolver` | 5.3.3 | 5 / 1 | Modern XML catalog resolver. Resolves DTDs, schemas, and other XML entities via OASIS XML catalogs. Replacement for the legacy `xml-resolver`. | **HIGH** — Entity resolution can trigger network requests to arbitrary URLs (SSRF) and read local files. A malicious catalog could redirect resolution to attacker-controlled resources. |
| **Legacy XML Resolver** | `xml-resolver:xml-resolver` | 1.2 | 0 / 0 | Legacy OASIS XML catalog resolver. Declared as a dependency but not directly imported in source (likely used transitively by Ant/Xerces). | **HIGH** — Same risks as xmlresolver above. Legacy library with no active maintenance. |

### MEDIUM Priority — Data Processing and Transformation

These libraries handle data parsing/transformation but don't directly access the file system or network.

| Dependency | Maven Coordinates | Version | Files (main/test) | Usage | Sandboxing Rationale |
|---|---|---|---|---|---|
| **Jackson** | `com.fasterxml.jackson.core:jackson-core/databind` + `jackson-dataformat-yaml` | 2.19.0 | 8 / 3 | JSON and YAML parsing/serialization. Used for project configuration files, plugin descriptors, and structured data I/O. ObjectMapper, JsonGenerator, JsonParser, YAMLMapper are the primary classes used. | **MEDIUM** — Deserialization vulnerabilities (polymorphic type handling) are a well-known Jackson attack vector. However, DITA-OT appears to use it for configuration parsing with known schemas, reducing risk. |
| **Google Guava** | `com.google.guava:guava` | 33.4.8-jre | 21 / 0 | Collection utilities: `ImmutableMap`, `SetMultimap`, `Sets`, `Strings`, hashing (`Hashing.md5/sha256`), base encoding, `@VisibleForTesting` annotation. Used exclusively in main (non-test) code. | **MEDIUM** — Primarily in-memory utilities. The `Hashing` usage could be a concern if used for security-critical operations (MD5 is weak). Low direct risk but large transitive dependency surface. |
| **Jing (RELAX NG)** | `org.relaxng:jing` | 20241231 | 0 / 0 | RELAX NG schema validation. Not directly imported but provides the `com.thaiopensource` classes used via the Jing library (7 files). Validates DITA content against RELAX NG schemas, including compact syntax support. | **MEDIUM** — Schema validation parses user-supplied schemas and content. Could be used to trigger resource exhaustion or entity expansion attacks through crafted schemas. |
| **Thaiopensource (via Jing)** | (part of jing) | — | 7 / 0 | RELAX NG validation internals: schema parsing (compact and SAX), pattern matching, ID type mapping, validation, schema building. Deeply integrated for content validation. | **MEDIUM** — Same as Jing above. |
| **ICU4J** | `com.ibm.icu:icu4j` | 77.1 | 1 / 0 | Internationalization: `Collator` for locale-aware string comparison. Used in index processing for proper sorting of index entries across languages. | **MEDIUM** — Large library (17MB+) but limited usage surface. Processes locale data which could potentially be crafted, but attack surface is minimal. |
| **XML APIs** | `xml-apis:xml-apis` | 1.4.01 | 0 / 0 | Standard XML API interfaces (DOM, SAX, StAX). Provides the API contracts that Xerces and other parsers implement. No direct imports (used transitively). | **MEDIUM** — API-only library with no implementation. Risk comes from the implementations (Xerces, Saxon) rather than the API itself. |

### LOW Priority — Logging and Utilities

These libraries are low-risk from a sandboxing perspective.

| Dependency | Maven Coordinates | Version | Files (main/test) | Usage | Sandboxing Rationale |
|---|---|---|---|---|---|
| **SLF4J** | `org.slf4j:slf4j-api` | 2.0.17 | 6 / 1 | Logging facade. `Logger` interface used across the codebase for diagnostic logging. `MarkerIgnoringBase` used in one custom logger implementation. | **LOW** — Logging API with no file/network access of its own. Risk only if a malicious logging backend is injected. |
| **Logback** | `ch.qos.logback:logback-classic` | 1.5.19 | 1 / 0 | SLF4J logging backend. Used in one file (`Main.java` or similar) to configure logging: `LoggerContext`, `PatternLayoutEncoder`, `FileAppender`. | **LOW** — Writes to log files, but this is controlled by the application, not user input. Known JNDI/deserialization vulnerabilities in older versions, but 1.5.x is patched. Configuration-based attacks (logback.xml injection) are possible but unlikely in this context. |

---

## Test-Only Dependencies

These are only used during testing and never shipped in production.

| Dependency | Maven Coordinates | Version | Files | Usage |
|---|---|---|---|---|
| **JUnit Jupiter** | `org.junit.jupiter:junit-jupiter-engine/params` | 6.0.2 | 129 | Test framework. `@Test`, `@BeforeEach`, `@ParameterizedTest`, assertions, etc. |
| **AssertJ** | `org.assertj:assertj-core` | 3.27.3 | 2 | Fluent assertion library for tests. |
| **XMLUnit** | `org.xmlunit:xmlunit-core` | 2.10.2 | 5 | XML comparison/diffing in tests. `DiffBuilder`, `Diff`. |
| **HTML Parser (nu.validator)** | `nu.validator:htmlparser` | 1.4.16 | 2 | HTML5 parsing in tests. `HtmlDocumentBuilder` for parsing HTML output. |
| **XSpec** | `io.xspec:xspec` | 3.2.2 | 0 | XSLT unit testing framework. Used via Gradle/Ant integration, not direct Java imports. |
| **OpenTest4J** | `org.opentest4j:TestAbortedException` | (transitive) | 1 | Test infrastructure exception. |

---

## Sandboxing Recommendations

### 1. Saxon XSLT Engine (Critical)
Saxon is the highest-priority target for sandboxing because:
- It executes user-supplied XSLT stylesheets, which are Turing-complete programs
- `xsl:result-document` can write arbitrary files
- Java extension functions can execute arbitrary code
- `doc()`, `unparsed-text()`, `document()` can read files and URLs
- **Recommendation:** Restrict Saxon's `Configuration` to disable Java extension functions, limit `xsl:result-document` to a specific output directory, and use a custom `ResourceResolver` that restricts URL access.

### 2. XML Parsing (Xerces + Entity Resolution)
- XXE (XML External Entity) attacks are a classic vulnerability
- Entity resolution can trigger SSRF
- **Recommendation:** Ensure `FEATURE_SECURE_PROCESSING` is enabled, disable external DTD/entity loading where possible, and restrict entity resolution to known catalogs.

### 3. Apache Ant Runtime
- Ant is the execution framework and has full system access
- **Recommendation:** If DITA-OT runs untrusted content, Ant task execution should be restricted to known safe tasks. A SecurityManager (or its modern replacement) could limit Ant's capabilities.

### 4. File System Operations (Commons IO)
- File copying, deletion, and path manipulation could be exploited via path traversal
- **Recommendation:** Validate and canonicalize all file paths. Restrict operations to a designated output directory.

### 5. Jackson Deserialization
- Polymorphic deserialization vulnerabilities are well-documented
- **Recommendation:** Ensure `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES` is used, avoid `enableDefaultTyping()`, and validate input schemas.

---

## Dependency Graph Overview

```
DITA-OT Core
├── Apache Ant (execution framework)
│   ├── ant-launcher
│   └── ant-apache-resolver → xml-resolver (legacy)
├── Saxon-HE (XSLT/XPath engine)
├── Xerces (XML parsing)
│   └── xml-apis
├── xmlresolver (modern XML catalog resolution)
├── Jing (RELAX NG validation)
│   └── com.thaiopensource.* classes
├── Jackson (JSON/YAML)
│   ├── jackson-core
│   ├── jackson-databind
│   └── jackson-dataformat-yaml
├── Guava (collections/utilities)
├── Commons IO (file utilities)
├── ICU4J (internationalization)
├── SLF4J + Logback (logging)
└── [Test only]
    ├── JUnit Jupiter
    ├── AssertJ
    ├── XMLUnit
    ├── nu.validator htmlparser
    └── XSpec
```
