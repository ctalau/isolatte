# Benchmark results

Machine: 4 vCPU, Linux-6.18.44-fc-v114-x86_64-with-glibc2.39. Produced by `./bench.sh`; raw output in [bench-raw.txt](bench-raw.txt).

Wall times include VM startup (median of 3 runs for Hello and the demo, one run otherwise). XmlBench parses a ~400 KB document with one XInclude 10 times; CpuBench runs 5 rounds at size 20000. *First* is the first round inside the guest (cold), *best* the fastest later round (warm).

| Configuration | Hello wall | Demo wall | XmlBench first | XmlBench best | XmlBench wall | CpuBench first | CpuBench best | CpuBench wall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| HotSpot (JIT), OpenJDK library | 98 ms | 199 ms | 146 ms | 13 ms | 421 ms | 61 ms | 24 ms | 258 ms |
| HotSpot -Xint, OpenJDK library | 85 ms | 240 ms | 547 ms | 448 ms | 4.94 s | 163 ms | 140 ms | 849 ms |
| HotSpot + TeaVM java.io (variant 1) | 201 ms | 277 ms | 102 ms | 12 ms | 558 ms | 32 ms | 9 ms | 262 ms |
| own interpreter + TeaVM library | 1.23 s | 3.46 s | 5.86 s | 1.33 s | 18.85 s | 8.03 s | 902 ms | 20.94 s |
| own interpreter, host C1 only | 993 ms | 1.16 s | 3.41 s | 2.58 s | 28.46 s | 2.21 s | 1.85 s | 10.68 s |
| miniJVM (JIT) + TeaVM library | 711 ms | 1.57 s | 1.13 s | 264 ms | 4.49 s | 301 ms | 157 ms | 1.54 s |
| miniJVM (no JIT) + TeaVM library | 737 ms | 1.69 s | 1.65 s | 675 ms | 8.43 s | 421 ms | 287 ms | 2.11 s |

Sanity: hotspot: outputs as expected; hotspot-xint: outputs as expected; hotspot-teavmio: outputs as expected; interp: outputs as expected; interp-c1: outputs as expected; minijvm: outputs as expected; minijvm-nojit: outputs as expected.
CpuBench checksums: ['check 9548064060'] (one value means all configurations computed the same result).
