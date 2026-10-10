# JVM versus TeaVM/Node

The JVM was faster in this experiment. Repeated transformations took about **1.5–5.7 times longer** in the TeaVM JavaScript build, depending on document size and whether the compiled stylesheet was reused. These are measurements of this adapted Saxon flow, not a general Saxon or TeaVM performance claim.

## Results

Times below are milliseconds per transformation, reported as the median of three process-fork medians. Warmup calls are excluded.

| Input | Stylesheet handling | JVM | TeaVM/Node | Node / JVM |
| --- | --- | ---: | ---: | ---: |
| Sample, 162 bytes | Compile each call | 3.097 | 4.567 | 1.47× |
| Sample, 162 bytes | Cached | 0.545 | 1.159 | 2.13× |
| 1,000 books, 68,809 bytes | Compile each call | 7.124 | 18.086 | 2.54× |
| 1,000 books, 68,809 bytes | Cached | 3.522 | 12.049 | 3.42× |
| 10,000 books, 697,909 bytes | Compile each call | 21.772 | 110.230 | 5.06× |
| 10,000 books, 697,909 bytes | Cached | 17.134 | 97.336 | 5.68× |

Fresh-process wall time for the sample was **1.034 seconds on the JVM versus 1.533 seconds in Node** (median of seven launches each, 1.48×). Ranges were 0.816–1.275 seconds and 1.331–1.783 seconds respectively. This includes runtime startup, file reads, module/class loading, stylesheet compilation, transformation and result reporting. It is not a measurement of runtime startup alone.

## Method

Both runtimes use the same Java transformation implementation and dependency versions: Saxon-HE 12.10, Xerces-J 2.12.2, TeaVM 0.16.0. JVM execution uses the original dependency bytecode; Node uses the compatibility adaptations documented in the README. The JavaScript artifact is nonminified and contains 40,057,732 bytes. Runtime versions were Node v24.19.0 and Corretto 21.0.12.1, on Linux x64.

`benchmark.mjs` starts runtime processes serially and alternates JVM/Node launch order across forks. It invokes Java directly, without the Node reference-runner wrapper. Each workload/mode uses three fresh processes per runtime:

| Input | Warmup calls per process | Measured calls per process |
| --- | ---: | ---: |
| Sample | 100 | 150 |
| 1,000 books | 30 | 60 |
| 10,000 books | 15 | 30 |

The sample uses the existing sample stylesheet. Larger inputs use ten-category grouping, sorting, counting, summing prices and formatting numbers, with a small text result. The harness generates these fixtures under `target/benchmark`.

For repeated-call measurements, input file reads occur before timing. Compile-each-call mode includes processor construction, stylesheet compilation, XML parsing, transformation and serialization. Cached mode creates the processor and compiled stylesheet before timing, but still creates a fresh transformer, parses XML and serializes the result for every call. Per-call timings use `System.nanoTime()`; no forced garbage collections occur. Raw records include individual process medians, p95s, means and outer wall times in [benchmark.json](results/benchmark.json).

Every benchmark pair checks output length and Java string hash equality. Separately, the functional regression suite passed all 21 checks, including exact JVM/Node output comparisons for all nine successful cases; see [verification.txt](results/verification.txt).

## Reproduce

With JDK 21, Maven and Node installed:

```sh
mvn -B clean package
mvn -B org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath \
  -Dmdep.outputFile=target/classpath.txt
node verify.mjs --jvm
node benchmark.mjs
```

Run these from this experiment's directory. `JAVA_HOME` selects the JDK. The benchmark overwrites `results/benchmark.json`.

## Assessment and limits

The adapted Saxon flow works and produces matching tested results, but it does not match JVM speed here. Caching stylesheets improves absolute latency on both runtimes; the relative gap remains and grows with input size in these workloads. The measurements do not identify the cause of that gap.

This was a single shared execution environment with an uncharacterized CPU quota and competing host load. The corpus is small and synthetic, warmup is finite, and no memory, concurrency, maximum-throughput or minified-build measurements were taken. Treat the numbers as an initial comparison rather than a portable capacity estimate.

The port is feasible for the tested in-memory functionality. JVM-equivalent performance has not been established. Next, benchmark representative project stylesheets and a minified build, then profile parsing, tree construction and transformation separately before choosing further optimizations or another backend.
