# QEMU Software Emulation: Hello World (AArch64 on x86_64)

This experiment demonstrates running a non-native ARM64 (`AArch64`) binary on an `x86_64` host using **QEMU user-mode software emulation** (`qemu-aarch64-static`).

## 1) Install QEMU user emulation and cross compiler

```bash
sudo apt-get update
sudo apt-get install -y qemu-user-static gcc-aarch64-linux-gnu
```

Result: packages installed successfully, including `qemu-user-static` and `gcc-aarch64-linux-gnu`.

## 2) Create a hello-world C program

File: `hello.c`

```c
#include <stdio.h>

int main(void) {
    puts("Hello from AArch64 via QEMU user-mode emulation!");
    return 0;
}
```

## 3) Cross-compile for AArch64

```bash
aarch64-linux-gnu-gcc -static -O2 -o hello-aarch64 hello.c
```

## 4) Verify the target architecture

```bash
readelf -h hello-aarch64 | sed -n '1,20p'
```

Relevant output:

```text
Machine:                           AArch64
```

## 5) Execute via QEMU software emulation

```bash
qemu-aarch64-static hello-aarch64
```

Observed output:

```text
Hello from AArch64 via QEMU user-mode emulation!
```

## Conclusion

QEMU user-mode emulation successfully executed an ARM64 Linux binary on an x86_64 host without hardware virtualization. The hello-world command completed normally and printed the expected message.
