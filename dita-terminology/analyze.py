#!/usr/bin/env python3
"""
Analyze DITA content for terminology: n-grams of length 1-5.
For each n-gram appearing >= 2 times, record count and whether it is
the complete text content of some XML element.
"""

import os
import re
import sys
from collections import defaultdict
from xml.etree import ElementTree as ET

DITA_DIR = os.path.join(os.path.dirname(__file__), "userguide", "DITA")
OUTPUT_DIR = os.path.dirname(__file__)


def iter_all_text(element):
    """Yield text pieces from element and all descendants (depth-first, in order)."""
    if element.text:
        yield element.text
    for child in element:
        yield from iter_all_text(child)
        if child.tail:
            yield child.tail


def normalize(text):
    """Lowercase and collapse whitespace."""
    return " ".join(text.lower().split())


def word_tokenize(text):
    """
    Split normalized text into word tokens.
    Strip leading/trailing punctuation from each token, drop empty tokens.
    """
    tokens = []
    for raw in text.split():
        # strip surrounding punctuation but keep hyphens inside words
        token = re.sub(r"^[^\w]+|[^\w]+$", "", raw, flags=re.UNICODE)
        if token:
            tokens.append(token)
    return tokens


def collect_element_texts(element):
    """
    Yield the word-tokenized text of every LEAF element in the tree
    (elements with no child elements) whose direct text content, when
    tokenized, yields between 1 and 5 words.  Using leaf elements only
    ensures the * mark means the element wraps exactly those words and
    nothing else (no embedded child tags, no stray trailing punctuation
    contributed by child tails).
    """
    if len(element) == 0:
        # Leaf element: only direct text, no child elements
        text = normalize(element.text or "")
        if text:
            words = word_tokenize(text)
            if 1 <= len(words) <= 5:
                yield " ".join(words)
    else:
        for child in element:
            yield from collect_element_texts(child)


def parse_file(filepath):
    """
    Return (tokens_list, element_phrases_set) for a single DITA file.
    tokens_list: flat list of word tokens from the whole document.
    element_phrases: set of normalized n-gram phrases (1-5 words) that appear
                     as the complete text of some element.
    """
    # Strip DOCTYPE declarations which ElementTree can't resolve
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError:
        return [], set()

    # Remove DOCTYPE declaration to avoid network/file resolution.
    # Standard DITA DOCTYPEs have no '>' inside their content, so [^>]* is safe.
    raw = re.sub(r"<!DOCTYPE[^>]*>", "", raw)

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return [], set()

    # Full token stream
    full_text = normalize("".join(iter_all_text(root)))
    tokens = word_tokenize(full_text)

    # Element phrases
    element_phrases = set(collect_element_texts(root))

    return tokens, element_phrases


def main():
    # Discover DITA files
    dita_files = []
    for dirpath, _dirs, files in os.walk(DITA_DIR):
        for fname in files:
            if fname.endswith(".dita"):
                dita_files.append(os.path.join(dirpath, fname))

    print(f"Found {len(dita_files)} DITA files", flush=True)

    # Per-length accumulators
    counts = [defaultdict(int) for _ in range(6)]   # index 1..5
    marked = [set() for _ in range(6)]               # index 1..5

    for i, filepath in enumerate(dita_files, 1):
        if i % 200 == 0:
            print(f"  Processing file {i}/{len(dita_files)} ...", flush=True)

        tokens, element_phrases = parse_file(filepath)

        # Count n-grams from the token stream
        for n in range(1, 6):
            for j in range(len(tokens) - n + 1):
                ngram = " ".join(tokens[j : j + n])
                counts[n][ngram] += 1

        # Record which n-grams are element-marked
        for phrase in element_phrases:
            words = phrase.split()
            n = len(words)
            if 1 <= n <= 5:
                marked[n].add(phrase)

    # Write output files
    for n in range(1, 6):
        outpath = os.path.join(OUTPUT_DIR, f"ngrams_{n}.txt")
        entries = [(seq, cnt) for seq, cnt in counts[n].items() if cnt >= 2]
        entries.sort(key=lambda x: -x[1])

        with open(outpath, "w", encoding="utf-8") as f:
            for seq, cnt in entries:
                star = " *" if seq in marked[n] else ""
                f.write(f"{seq}\t{cnt}{star}\n")

        print(f"Wrote {len(entries)} entries to {outpath}")


if __name__ == "__main__":
    main()
