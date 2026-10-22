"""Build the single-file browser validator page.

usage: python3 -I build_page.py TEMPLATE.html VALIDATOR.wasm OUT.html
Replaces the __WASM_BASE64__ placeholder in the template with the wasm build
of compiled/rust (see `cargo build --lib --target wasm32-unknown-unknown`)."""
import base64
import sys

template, wasm, out = sys.argv[1:4]
page = open(template, encoding="utf-8").read()
assert page.count("__WASM_BASE64__") == 1
data = base64.b64encode(open(wasm, "rb").read()).decode()
open(out, "w", encoding="utf-8").write(page.replace("__WASM_BASE64__", data))
print(f"{out}: {len(page) + len(data) - len('__WASM_BASE64__')} bytes (wasm {len(data)} base64)")
