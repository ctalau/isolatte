#!/usr/bin/env python3
"""Chunked FOP renderer with adaptive OOM splitting.

Flow:
1) Split full FO by page-sequence (+ optional top-level flow split).
2) Render each chunk under bounded heap.
3) If a chunk OOMs and adaptive mode is enabled, probe-render ~1MB prefix,
   then split failed chunk into two parts at probe boundary and retry.
4) Merge successful chunk PDFs.
"""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import time
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path

try:
    from pypdf import PdfMerger, PdfReader
except Exception:  # pragma: no cover
    PdfMerger = None
    PdfReader = None

FO_NS = "http://www.w3.org/1999/XSL/Format"
FO = f"{{{FO_NS}}}"


def read_rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except FileNotFoundError:
        return 0
    return 0


def split_page_sequence_by_flow(page_sequence: ET.Element, flow_split_size: int) -> list[ET.Element]:
    if flow_split_size <= 0:
        return [copy.deepcopy(page_sequence)]

    flow = None
    non_flow_children = []
    for child in page_sequence:
        if child.tag == FO + "flow" and flow is None:
            flow = child
        else:
            non_flow_children.append(child)

    if flow is None:
        return [copy.deepcopy(page_sequence)]

    flow_children = list(flow)
    if len(flow_children) <= flow_split_size:
        return [copy.deepcopy(page_sequence)]

    parts: list[ET.Element] = []
    for i in range(0, len(flow_children), flow_split_size):
        ps = ET.Element(page_sequence.tag, page_sequence.attrib)
        for child in non_flow_children:
            ps.append(copy.deepcopy(child))
        new_flow = ET.Element(flow.tag, flow.attrib)
        for node in flow_children[i : i + flow_split_size]:
            new_flow.append(copy.deepcopy(node))
        ps.append(new_flow)
        parts.append(ps)
    return parts


def chunk_fo(input_fo: Path, chunk_size: int, workdir: Path, keep_bookmarks: bool, flow_split_size: int) -> list[Path]:
    tree = ET.parse(input_fo)
    root = tree.getroot()
    if root.tag != FO + "root":
        raise RuntimeError(f"Unexpected root element: {root.tag}")

    raw_page_sequences = [c for c in root if c.tag == FO + "page-sequence"]
    page_sequences = []
    for ps in raw_page_sequences:
        page_sequences.extend(split_page_sequence_by_flow(ps, flow_split_size))

    scaffold = [c for c in root if c.tag != FO + "page-sequence"]
    if not keep_bookmarks:
        scaffold = [c for c in scaffold if c.tag != FO + "bookmark-tree"]

    out_files: list[Path] = []
    for i in range(0, len(page_sequences), chunk_size):
        chunk_idx = i // chunk_size + 1
        chunk_root = ET.Element(root.tag, root.attrib)
        for child in scaffold:
            chunk_root.append(copy.deepcopy(child))
        for ps in page_sequences[i : i + chunk_size]:
            chunk_root.append(copy.deepcopy(ps))
        out_path = workdir / f"chunk-{chunk_idx:04d}.fo"
        ET.ElementTree(chunk_root).write(out_path, encoding="utf-8", xml_declaration=True)
        out_files.append(out_path)
    return out_files


def run_fop_chunk(chunk_fo_path: Path, chunk_pdf: Path, cp: str, xmx: str, relaxed: bool, conserve: bool, sample_ms: int) -> dict:
    cmd = [
        "java", f"-Xmx{xmx}", f"-Xms{xmx}", "-Djava.awt.headless=true",
        "-cp", cp, "org.apache.fop.cli.Main",
    ]
    if relaxed:
        cmd.append("-r")
    if conserve:
        cmd.append("-conserve")
    cmd += ["-fo", str(chunk_fo_path), "-pdf", str(chunk_pdf)]

    t0 = time.perf_counter()
    peak = 0
    log = chunk_pdf.with_suffix(".log")
    with log.open("w", encoding="utf-8") as lf:
        p = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT, text=True)
        while p.poll() is None:
            peak = max(peak, read_rss_kb(p.pid))
            time.sleep(sample_ms / 1000.0)
        rc = p.wait()

    oom = False
    try:
        txt = log.read_text(encoding="utf-8", errors="ignore")
        oom = "OutOfMemoryError" in txt
    except Exception:
        pass

    pages = None
    if rc == 0 and PdfReader is not None:
        try:
            pages = len(PdfReader(str(chunk_pdf)).pages)
        except Exception:
            pages = None

    return {
        "chunk_fo": str(chunk_fo_path),
        "chunk_pdf": str(chunk_pdf),
        "exit_code": rc,
        "elapsed_s": round(time.perf_counter() - t0, 2),
        "peak_rss_kb": peak,
        "peak_rss_mb": round(peak / 1024.0, 1),
        "pages": pages,
        "oom": oom,
        "log": str(log),
    }


def load_single_sequence(chunk_fo_path: Path):
    tree = ET.parse(chunk_fo_path)
    root = tree.getroot()
    seqs = [c for c in root if c.tag == FO + "page-sequence"]
    if len(seqs) != 1:
        return None
    ps = seqs[0]

    flow = None
    non_flow_children = []
    for child in ps:
        if child.tag == FO + "flow" and flow is None:
            flow = child
        else:
            non_flow_children.append(child)
    if flow is None:
        return None

    flow_children = list(flow)
    if len(flow_children) >= 2:
        return {
            "root": root,
            "ps": ps,
            "flow": flow,
            "non_flow": non_flow_children,
            "mode": "flow",
            "split_parent": flow,
            "split_children": flow_children,
        }

    # fallback: if flow has a single giant block, split inside that block
    if len(flow_children) == 1:
        nested = flow_children[0]
        nested_children = list(nested)
        if len(nested_children) >= 2:
            return {
                "root": root,
                "ps": ps,
                "flow": flow,
                "non_flow": non_flow_children,
                "mode": "nested",
                "nested_template": nested,
                "split_parent": nested,
                "split_children": nested_children,
            }

    return None


def write_split_chunk(loaded, flow_nodes: list[ET.Element], out_path: Path) -> None:
    root = loaded["root"]
    ps = loaded["ps"]
    flow = loaded["flow"]
    non_flow_children = loaded["non_flow"]
    mode = loaded["mode"]

    new_root = ET.Element(root.tag, root.attrib)
    for child in root:
        if child is ps:
            new_ps = ET.Element(ps.tag, ps.attrib)
            for c in non_flow_children:
                new_ps.append(copy.deepcopy(c))

            new_flow = ET.Element(flow.tag, flow.attrib)
            if mode == "flow":
                for n in flow_nodes:
                    new_flow.append(copy.deepcopy(n))
            else:
                nested_template = loaded["nested_template"]
                nested_new = ET.Element(nested_template.tag, nested_template.attrib)
                nested_new.text = nested_template.text
                nested_new.tail = nested_template.tail
                for n in flow_nodes:
                    nested_new.append(copy.deepcopy(n))
                new_flow.append(nested_new)

            new_ps.append(new_flow)
            new_root.append(new_ps)
        else:
            new_root.append(copy.deepcopy(child))
    ET.ElementTree(new_root).write(out_path, encoding="utf-8", xml_declaration=True)


def choose_probe_cut(flow_children: list[ET.Element], probe_bytes: int) -> int:
    acc = 0
    cut = 0
    for i, node in enumerate(flow_children, 1):
        acc += len(ET.tostring(node, encoding="utf-8"))
        cut = i
        if acc >= probe_bytes:
            break
    if cut <= 0:
        cut = 1
    if cut >= len(flow_children):
        cut = len(flow_children) // 2
    return max(1, cut)


def adaptive_split_failed_chunk(
    failed_fo: Path,
    workdir: Path,
    cp: str,
    xmx: str,
    relaxed: bool,
    conserve: bool,
    sample_ms: int,
    probe_bytes: int,
    split_counter: int,
) -> tuple[list[Path], dict] | tuple[None, dict]:
    loaded = load_single_sequence(failed_fo)
    if loaded is None:
        return None, {"reason": "chunk_not_splittable"}

    flow_children = loaded["split_children"]
    cut = choose_probe_cut(flow_children, probe_bytes)

    # Probe render first piece (~probe_bytes from beginning)
    probe_fo = workdir / f"probe-{split_counter:04d}.fo"
    probe_pdf = workdir / f"probe-{split_counter:04d}.pdf"
    write_split_chunk(loaded, flow_children[:cut], probe_fo)
    probe_result = run_fop_chunk(probe_fo, probe_pdf, cp, xmx, relaxed, conserve, sample_ms)

    if probe_result["exit_code"] != 0 and cut > 1:
        # fallback to binary split if 1MB prefix still OOMs
        cut = max(1, len(flow_children) // 2)

    part_a = workdir / f"split-{split_counter:04d}-a.fo"
    part_b = workdir / f"split-{split_counter:04d}-b.fo"
    write_split_chunk(loaded, flow_children[:cut], part_a)
    write_split_chunk(loaded, flow_children[cut:], part_b)

    info = {
        "reason": "adaptive_split",
        "cut_index": cut,
        "flow_children": len(flow_children),
        "split_mode": loaded.get("mode"),
        "probe_pages": probe_result.get("pages"),
        "probe_result": probe_result,
        "part_a": str(part_a),
        "part_b": str(part_b),
    }
    return [part_a, part_b], info


def merge_pdfs(chunk_pdfs: list[Path], out_pdf: Path) -> None:
    if PdfMerger is None:
        raise RuntimeError("pypdf is required to merge chunk PDFs. Install with: pip install pypdf")
    merger = PdfMerger()
    for pdf in chunk_pdfs:
        merger.append(str(pdf))
    with out_pdf.open("wb") as f:
        merger.write(f)
    merger.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fo", required=True, type=Path)
    ap.add_argument("--out-pdf", required=True, type=Path)
    ap.add_argument("--workdir", required=True, type=Path)
    ap.add_argument("--chunk-size", type=int, default=1)
    ap.add_argument("--cp-file", required=True, type=Path)
    ap.add_argument("--prepend-jar", action="append", default=[])
    ap.add_argument("--xmx", default="256m")
    ap.add_argument("--relaxed", action="store_true")
    ap.add_argument("--conserve", action="store_true")
    ap.add_argument("--sample-ms", type=int, default=200)
    ap.add_argument("--keep-bookmarks", action="store_true")
    ap.add_argument("--flow-split-size", type=int, default=0)
    ap.add_argument("--adaptive-oom-split", action="store_true",
                    help="On OOM, split failed single-sequence chunk into 2 and retry.")
    ap.add_argument("--probe-bytes", type=int, default=1024 * 1024,
                    help="Prefix bytes for probe split from the beginning of failed chunk.")
    args = ap.parse_args()

    args.workdir.mkdir(parents=True, exist_ok=True)
    args.out_pdf.parent.mkdir(parents=True, exist_ok=True)

    cp = ":".join([*args.prepend_jar, args.cp_file.read_text(encoding="utf-8").strip()])
    initial_chunks = chunk_fo(args.fo, args.chunk_size, args.workdir, args.keep_bookmarks, args.flow_split_size)

    queue = deque(initial_chunks)
    rendered_pdfs: list[Path] = []
    results: list[dict] = []
    split_events: list[dict] = []
    split_counter = 1

    while queue:
        fo_chunk = queue.popleft()
        pdf_chunk = args.workdir / (fo_chunk.stem + ".pdf")
        result = run_fop_chunk(fo_chunk, pdf_chunk, cp, args.xmx, args.relaxed, args.conserve, args.sample_ms)
        results.append(result)

        if result["exit_code"] == 0:
            rendered_pdfs.append(pdf_chunk)
            continue

        if not (args.adaptive_oom_split and result.get("oom", False)):
            print(json.dumps({"status": "failed", "failed_chunk": str(fo_chunk), "results": results,
                              "split_events": split_events}, indent=2))
            return 1

        new_chunks, event = adaptive_split_failed_chunk(
            fo_chunk, args.workdir, cp, args.xmx, args.relaxed, args.conserve, args.sample_ms,
            args.probe_bytes, split_counter
        )
        split_counter += 1
        event["failed_chunk"] = str(fo_chunk)
        split_events.append(event)

        if new_chunks is None:
            print(json.dumps({"status": "failed", "failed_chunk": str(fo_chunk), "results": results,
                              "split_events": split_events}, indent=2))
            return 1

        # prepend in order: first part then second part
        queue.appendleft(new_chunks[1])
        queue.appendleft(new_chunks[0])

    merge_pdfs(rendered_pdfs, args.out_pdf)
    summary = {
        "status": "ok",
        "chunks_rendered": len(rendered_pdfs),
        "merged_pdf": str(args.out_pdf),
        "max_chunk_peak_rss_mb": max((r["peak_rss_mb"] for r in results), default=0),
        "split_events": split_events,
        "results": results,
    }
    (args.workdir / "chunked-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
