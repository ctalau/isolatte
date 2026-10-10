# TeaVM + Xerces-J inside Node

This experiment compiles Apache Xerces-J 2.12.2 to JavaScript with TeaVM 0.16.0 and parses an XML file in Node. Java is needed only at build time; running `run.mjs` launches no JVM or Java subprocess. Each invocation reads the selected file as strictly decoded UTF-8 and passes its contents to Xerces through a Java `StringReader`.

**Result:** the adapted build works. Ten checks pass for namespaces, Unicode, CDATA, entity/JSON escaping, malformed input, DOCTYPE rejection, invalid UTF-8 and missing files. The original unadapted build failed on reflective factory loading and an unsupported Java exception class. See [verification evidence](results/verification.txt) and [original compiler diagnostics](results/unadapted-build.txt).

## Reproduce

Requirements: JDK 21, Maven 3.9+, Node 18+. Measured with Corretto 21.0.12.1, Maven 3.9.9 and Node 24.19.0. Maven downloads pinned TeaVM and Xerces dependencies from Maven Central.

```sh
cd teavm-node-xerces
mvn -B clean package
node verify.mjs
node run.mjs
node run.mjs /absolute/path/to/your.xml
```

Successful parsing prints one JSON object with the parser/version, root QName, namespace URI, element count and concatenated text content. Errors print to stderr and exit with status 1.

## Compatibility adaptations

1. Construct `SAXParser` with `NonValidatingConfiguration`, whose overridden datatype factory directly creates `DTDDVFactoryImpl`. This removes the reachable reflective class-loader and SecurityManager calls.
2. Use a TeaVM `ClassHolderTransformer` to change Xerces' `MalformedByteSequenceException` superclass from the missing `CharConversionException` to supported `IOException`, and redirect Xerces' catches of `CharConversionException` to `MalformedByteSequenceException`. Its existing constructor, fields and message implementation remain. No downloaded JAR is modified. The byte-decoding exception path is not exercised by the UTF-8/StringReader host flow.
3. Register Xerces' XML/SAX message bundles in `META-INF/services/java.util.ResourceBundle`, as required by TeaVM's compile-time bundle loader. This preserves useful parser diagnostics.
4. Initialize the namespace scanner before setting features. Otherwise `NonValidatingConfiguration` creates it lazily and installs defaults that reset the DOCTYPE restriction.

Xerces performs the XML parsing; there is no host XML parser. DTD declarations are rejected, and external general entities, parameter entities and DTD loading are disabled. Inputs cannot request additional resources through this parser configuration.

## Scope and assessment

This is a working feasibility experiment for nonvalidating XML 1.0 parsing. The nonminified generated CommonJS module measured 2,223,087 bytes. It uses SAX events rather than building a DOM, but collects all text for the summary. Both the host input and collected text reside in memory.

It does not provide schema/DTD validation, XML 1.1 coverage, arbitrary XML encodings, a browser UI or a tested WebAssembly target. The host assumes UTF-8 regardless of an XML encoding declaration. XML is parsed from characters, so byte-level encoding detection is outside Xerces in this flow. There are no input-size, memory or execution-time limits in the runner; this is not an isolation boundary. TeaVM compiles a fixed program ahead of time, rather than interpreting arbitrary Java bytecode as the separate Ristretto experiment does.

**Next:** test a representative XML corpus, exercise byte-stream parsing and exception behavior if arbitrary encodings are needed, then evaluate TeaVM's Wasm GC backend if WebAssembly is required. My assessment: TeaVM can run this narrowed Xerces parsing flow, as demonstrated, but a general Xerces port needs further compatibility work and validation.

References: [TeaVM Maven configuration](https://teavm.org/docs/tooling/maven.html), [TeaVM constraints](https://teavm.org/docs/intro/overview.html), [Xerces-J](https://xerces.apache.org/xerces2-j/).
