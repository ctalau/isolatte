#!/usr/bin/env python3
"""
Analyze DITA content for terminology: n-grams of length 1-5.
For each n-gram appearing >= 2 times, record count and whether it is
the complete text content of some XML element.

Stop-word filtering:
- Unigrams that are stop words are dropped entirely.
- N-grams (n>=2) whose first OR last token is a stop word are dropped.
  This removes phrases like "in the", "allows you to", "of the following"
  while keeping genuine terms like "dialog box", "content completion assistant".

Output:
  ngrams_N.txt        – all qualifying n-grams, count desc, * if marked up
  ngrams_N_starred.txt – only the starred (marked-up) subset
"""

import os
import re
from collections import defaultdict
from xml.etree import ElementTree as ET

DITA_DIR = os.path.join(os.path.dirname(__file__), "userguide", "DITA")
OUTPUT_DIR = os.path.dirname(__file__)

# ---------------------------------------------------------------------------
# Stop words: articles, prepositions, conjunctions, auxiliary verbs, pronouns,
# and other function words that cannot anchor a technical term.
# ---------------------------------------------------------------------------
STOP_WORDS = {
    # articles
    "a", "an", "the",
    # coordinating / subordinating conjunctions
    "and", "but", "or", "nor", "for", "yet", "so",
    "although", "because", "since", "unless", "until", "while",
    "though", "whether", "if", "once", "than", "that", "which",
    "who", "whom", "whose", "when", "where", "why", "how",
    # prepositions
    "at", "by", "in", "of", "on", "to", "up",
    "about", "above", "across", "after", "against", "along", "among",
    "around", "as", "before", "behind", "below", "beneath", "beside",
    "besides", "between", "beyond", "despite", "during", "except",
    "from", "inside", "into", "near", "off", "out", "outside",
    "over", "past", "per", "since", "through", "throughout", "toward",
    "towards", "under", "underneath", "until", "upon", "via",
    "with", "within", "without",
    # auxiliary / modal verbs
    "am", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "having",
    "do", "does", "did",
    "will", "would", "shall", "should", "may", "might", "must",
    "can", "could", "need", "dare", "ought",
    # pronouns
    "i", "me", "my", "myself",
    "you", "your", "yourself", "yourselves",
    "he", "him", "his", "himself",
    "she", "her", "hers", "herself",
    "it", "its", "itself",
    "we", "us", "our", "ours", "ourselves",
    "they", "them", "their", "theirs", "themselves",
    "this", "that", "these", "those",
    "what", "whatever", "whichever", "whoever",
    # common adverbs that never anchor terminology
    "not", "no", "also", "just", "very", "too", "so",
    "here", "there", "then", "now", "still", "already", "again",
    "always", "never", "often", "sometimes", "usually",
    "more", "most", "less", "least", "much", "many", "few",
    "only", "even", "both", "each", "all", "any", "every",
    "either", "neither", "other", "another",
    "same", "such", "own",
    # common verb forms that never anchor terminology on their own
    "make", "makes", "made",
    "get", "gets", "got",
    "go", "goes", "went",
    "come", "comes", "came",
    "take", "takes", "took",
    "give", "gives", "gave",
    "know", "knows", "knew",
    "see", "sees", "saw",
    "want", "wants", "wanted",
    "need", "needs", "needed",
    "allow", "allows", "allowed",
    "specify", "specifies", "specified",
    "click", "clicks", "clicked",
    "enter", "enters", "entered",
    "press", "presses", "pressed",
    # filler / connective phrases reduced to single words
    "following", "however", "therefore", "thus", "hence",
    "otherwise", "furthermore", "moreover", "additionally",
    "instead", "rather", "whether", "although", "provided",
    "including", "regarding", "according",
    "available", "used", "using", "based",
    "set", "sets",
}


def is_stop(word):
    return word in STOP_WORDS


def keep_ngram(tokens):
    """Return True if this n-gram should be kept (not filtered out)."""
    if len(tokens) == 1:
        return not is_stop(tokens[0])
    # For multi-word n-grams: reject if either boundary word is a stop word
    return not is_stop(tokens[0]) and not is_stop(tokens[-1])


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def iter_all_text(element):
    """Yield text pieces from element and all descendants (depth-first)."""
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
    Strip leading/trailing punctuation from each token; drop empty tokens.
    """
    tokens = []
    for raw in text.split():
        token = re.sub(r"^[^\w]+|[^\w]+$", "", raw, flags=re.UNICODE)
        if token:
            tokens.append(token)
    return tokens


def collect_element_texts(element):
    """
    Yield the word-tokenized text of every LEAF element in the tree
    (elements with no child elements) whose direct text content, when
    tokenized, yields between 1 and 5 words.  Leaf elements only: this
    ensures the * mark means the element wraps exactly those words with
    no embedded child tags contributing extra text.
    """
    if len(element) == 0:
        text = normalize(element.text or "")
        if text:
            words = word_tokenize(text)
            if 1 <= len(words) <= 5:
                yield " ".join(words)
    else:
        for child in element:
            yield from collect_element_texts(child)


# ---------------------------------------------------------------------------
# Per-file parsing
# ---------------------------------------------------------------------------

def parse_file(filepath):
    """Return (tokens_list, element_phrases_set) for a single DITA file."""
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

    full_text = normalize("".join(iter_all_text(root)))
    tokens = word_tokenize(full_text)
    element_phrases = set(collect_element_texts(root))
    return tokens, element_phrases


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    dita_files = []
    for dirpath, _dirs, files in os.walk(DITA_DIR):
        for fname in files:
            if fname.endswith(".dita"):
                dita_files.append(os.path.join(dirpath, fname))

    print(f"Found {len(dita_files)} DITA files", flush=True)

    counts = [defaultdict(int) for _ in range(6)]   # index 1..5
    marked = [set() for _ in range(6)]               # index 1..5

    for i, filepath in enumerate(dita_files, 1):
        if i % 200 == 0:
            print(f"  Processing file {i}/{len(dita_files)} ...", flush=True)

        tokens, element_phrases = parse_file(filepath)

        # Count n-grams, skipping those anchored on stop words
        for n in range(1, 6):
            for j in range(len(tokens) - n + 1):
                toks = tokens[j : j + n]
                if keep_ngram(toks):
                    counts[n][" ".join(toks)] += 1

        # Record which n-grams are element-marked (apply same filter)
        for phrase in element_phrases:
            words = phrase.split()
            n = len(words)
            if 1 <= n <= 5 and keep_ngram(words):
                marked[n].add(phrase)

    # Write output files
    for n in range(1, 6):
        entries = [(seq, cnt) for seq, cnt in counts[n].items() if cnt >= 2]
        entries.sort(key=lambda x: -x[1])

        starred = [(seq, cnt) for seq, cnt in entries if seq in marked[n]]

        outpath = os.path.join(OUTPUT_DIR, f"ngrams_{n}.txt")
        with open(outpath, "w", encoding="utf-8") as f:
            for seq, cnt in entries:
                star = " *" if seq in marked[n] else ""
                f.write(f"{seq}\t{cnt}{star}\n")

        starpath = os.path.join(OUTPUT_DIR, f"ngrams_{n}_starred.txt")
        with open(starpath, "w", encoding="utf-8") as f:
            for seq, cnt in starred:
                f.write(f"{seq}\t{cnt}\n")

        print(f"ngrams_{n}.txt: {len(entries)} entries, {len(starred)} starred")


if __name__ == "__main__":
    main()
