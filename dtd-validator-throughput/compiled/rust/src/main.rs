//! DTD validation of DITA topics with validators compiled from the DTDs.
//!
//! `generated.rs` (made by `compiled/gen.py`) holds every content model as a
//! minimized DFA plus the attribute declarations, as static tables; nothing
//! DTD-related is parsed at run time. quick-xml supplies the XML events.
//!
//! usage: dita-compiled-validator THREADS < file-list
//!   VERBOSE=1 prints errors; PARSE_ONLY=1 runs quick-xml without validating.

#[allow(dead_code, clippy::all)]
#[path = "../../../work-gen/generated.rs"]
mod generated;

use generated as g;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use std::collections::HashSet;
use std::io::{self, BufRead};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const EMPTY: u8 = 1;
const ANY: u8 = 2;
const MIXED: u8 = 3;
const ELEMENT: u8 = 4;
/// Content state after an error, so one bad child is reported once.
const DEAD: u32 = u32::MAX;

const T_CDATA: u8 = 0;
const T_ID: u8 = 1;
const T_IDREF: u8 = 2;
const T_IDREFS: u8 = 3;
const T_NMTOKEN: u8 = 6;
const T_NMTOKENS: u8 = 7;
const D_REQUIRED: u8 = 1;
const D_FIXED: u8 = 2;

struct Frame {
    kind: u8,
    state: u32,
}

struct Validator {
    shell: Option<&'static g::Shell>,
    doctype_name: String,
    stack: Vec<Frame>,
    ids: HashSet<String>,
    idrefs: Vec<String>,
    errors: usize,
    messages: Option<Vec<String>>,
}

fn is_name_start(c: char) -> bool {
    matches!(c, ':' | 'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}'
        | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}'
        | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

fn is_name(s: &str) -> bool {
    let mut cs = s.chars();
    cs.next().is_some_and(is_name_start) && cs.all(is_name_char)
}

fn is_nmtoken(s: &str) -> bool {
    !s.is_empty() && s.chars().all(is_name_char)
}

/// Non-CDATA attribute normalization: trim and collapse runs of spaces.
fn collapse(s: &str) -> std::borrow::Cow<'_, str> {
    let t = s.trim_matches(' ');
    if !t.contains("  ") {
        return t.into();
    }
    t.split(' ').filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ").into()
}

/// Replacement text of an internal general entity the DTD declares.
fn entity(shell: &'static g::Shell, name: &str) -> Option<&'static str> {
    let i = shell.entities.binary_search_by(|(n, _)| (*n).cmp(name)).ok()?;
    Some(shell.entities[i].1)
}

fn step(state: u32, sym: u16) -> Option<u32> {
    let (lo, hi) = (g::TRANS_OFF[state as usize] as usize, g::TRANS_OFF[state as usize + 1] as usize);
    let syms = &g::TRANS_SYM[lo..hi];
    syms.binary_search(&sym).ok().map(|i| g::TRANS_NEXT[lo + i])
}

fn is_ws(b: &[u8]) -> bool {
    b.iter().all(|&c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
}

impl Validator {
    fn new(verbose: bool) -> Self {
        Validator {
            shell: None,
            doctype_name: String::new(),
            stack: Vec::with_capacity(64),
            ids: HashSet::new(),
            idrefs: Vec::new(),
            errors: 0,
            messages: verbose.then(Vec::new),
        }
    }

    fn error(&mut self, msg: impl FnOnce() -> String) {
        self.errors += 1;
        if let Some(m) = &mut self.messages {
            m.push(msg());
        }
    }

    /// The document's DOCTYPE: `name PUBLIC "pub" "sys"`.
    fn doctype(&mut self, text: &str) {
        let name = text.split_whitespace().next().unwrap_or("");
        self.doctype_name = name.to_string();
        if text.contains('[') {
            return self.error(|| "internal DTD subsets are not supported".into());
        }
        let public = text.find("PUBLIC").and_then(|p| {
            let rest = &text[p + 6..];
            let a = rest.find(['"', '\''])?;
            let q = rest.as_bytes()[a] as char;
            let b = rest[a + 1..].find(q)?;
            Some(&rest[a + 1..a + 1 + b])
        });
        self.shell = public.and_then(|p| g::SHELLS.iter().find(|s| s.public_id == p));
        if self.shell.is_none() {
            let p = public.unwrap_or("").to_string();
            self.error(|| format!("no compiled DTD for public id '{p}'"));
        }
    }

    fn content_text(&mut self, whitespace: bool, cdata: bool) {
        let Some(top) = self.stack.last_mut() else { return };
        let bad = match top.kind {
            EMPTY => true,
            ELEMENT => !whitespace || cdata,
            _ => false,
        };
        if bad && top.state != DEAD {
            top.state = DEAD;
            self.error(|| "character data not allowed here".into());
        }
    }

    /// Returns false when the document cannot be validated further.
    fn start(&mut self, e: &BytesStart, shell: &'static g::Shell) -> bool {
        let name = e.name();
        let name = name.as_ref();
        let id = g::elem_id(name.as_bytes());
        let declared = id != g::NONE && shell.kind[id as usize] != 0;
        let lossy = || name.to_string();
        match self.stack.last_mut() {
            None => {
                if name != self.doctype_name {
                    self.error(|| format!("root element {} does not match DOCTYPE", lossy()));
                }
            }
            Some(parent) => match parent.kind {
                EMPTY | MIXED | ELEMENT if parent.state != DEAD => {
                    let next = if parent.kind == EMPTY || id == g::NONE { None } else { step(parent.state, id) };
                    match next {
                        Some(s) => parent.state = s,
                        None => {
                            parent.state = DEAD;
                            self.error(|| format!("element {} not allowed here", lossy()));
                        }
                    }
                }
                _ => {}
            },
        }
        if !declared {
            self.error(|| format!("no declaration for element {}", lossy()));
            self.stack.push(Frame { kind: ANY, state: DEAD });
            return true;
        }
        let i = id as usize;
        let al = shell.alist[i] as usize;
        let decls = &g::ALIST[g::ALIST_OFF[al] as usize..g::ALIST_OFF[al + 1] as usize];
        let mut required = 0u8;
        for attr in e.attributes() {
            let Ok(attr) = attr else {
                self.error(|| "malformed attribute".into());
                return false;
            };
            let key = attr.key.as_ref();
            let aid = g::attr_id(key.as_bytes());
            let Some(&d) = decls.iter().find(|&&d| g::AD_ATTR[d as usize] == aid) else {
                self.error(|| format!("no declaration for attribute {key}"));
                continue;
            };
            let resolve = |name: &str| resolve_predefined_entity(name).or_else(|| entity(shell, name));
            let Ok(raw) = attr.normalized_value_with(XmlVersion::Implicit1_0, 1, resolve) else {
                self.error(|| "bad attribute value".into());
                return false;
            };
            let d = d as usize;
            let atype = g::AD_TYPE[d];
            let value = if atype == T_CDATA { raw.clone() } else { collapse(&raw).into_owned().into() };
            let v: &str = &value;
            let ok = match atype {
                T_CDATA => true,
                T_ID => is_name(v) && self.ids.insert(v.to_string()),
                T_IDREF => is_name(v) && { self.idrefs.push(v.to_string()); true },
                T_IDREFS => v.split(' ').all(|r| is_name(r) && { self.idrefs.push(r.to_string()); true }),
                T_NMTOKEN => is_nmtoken(v),
                T_NMTOKENS => v.split(' ').all(is_nmtoken),
                8 | 9 => {
                    let ev = g::AD_ENUM[d] as usize;
                    g::ENUM_VALS[g::ENUM_OFF[ev] as usize..g::ENUM_OFF[ev + 1] as usize]
                        .iter()
                        .any(|&s| g::STRS[s as usize] == v.as_bytes())
                }
                _ => false, // ENTITY/ENTITIES: the DTDs declare no unparsed entities
            };
            if !ok {
                self.error(|| format!("bad value '{v}' for attribute {key}"));
            }
            match g::AD_DEFAULT[d] {
                D_REQUIRED => required += 1,
                D_FIXED if g::STRS[g::AD_FIXED[d] as usize] != v.as_bytes() => {
                    self.error(|| format!("attribute {key} must be fixed"));
                }
                _ => {}
            }
        }
        if required < shell.nreq[i] {
            self.error(|| format!("required attribute missing on {}", lossy()));
        }
        self.stack.push(Frame { kind: shell.kind[i], state: shell.start[i] });
        true
    }

    fn end(&mut self) {
        if let Some(f) = self.stack.pop() {
            if (f.kind == ELEMENT || f.kind == MIXED) && f.state != DEAD && !g::STATE_FINAL[f.state as usize] {
                self.error(|| "element content incomplete".into());
            }
        }
    }

    fn run(&mut self, text: &str) {
        let mut reader = Reader::from_str(text);
        let mut seen_root = false;
        loop {
            let ev = match reader.read_event() {
                Ok(ev) => ev,
                Err(e) => return self.error(|| format!("not well-formed: {e}")),
            };
            match ev {
                Event::DocType(t) => {
                    let s = t.to_string();
                    self.doctype(&s);
                }
                Event::Start(ref e) | Event::Empty(ref e) => {
                    let Some(shell) = self.shell else {
                        if !seen_root {
                            self.error(|| "no DTD found".into());
                        }
                        return;
                    };
                    seen_root = true;
                    if !self.start(e, shell) {
                        return;
                    }
                    if matches!(ev, Event::Empty(_)) {
                        self.end();
                    }
                }
                Event::End(_) => self.end(),
                Event::Text(t) => {
                    let ws = is_ws(t.as_bytes());
                    self.content_text(ws, false);
                }
                Event::CData(_) => self.content_text(false, true),
                Event::GeneralRef(r) => {
                    if r.is_char_ref() {
                        if !matches!(r.resolve_char_ref(), Ok(Some(_))) {
                            return self.error(|| "bad character reference".into());
                        }
                        self.content_text(false, false);
                    } else if matches!(r.as_ref(), "lt" | "gt" | "amp" | "quot" | "apos") {
                        self.content_text(false, false);
                    } else if let Some(text) = self.shell.and_then(|s| entity(s, &r)) {
                        self.content_text(is_ws(text.as_bytes()), false);
                    } else {
                        let n = r.to_string();
                        return self.error(|| format!("entity '{n}' not defined"));
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if !seen_root {
            return self.error(|| "no root element".into());
        }
        let missing: Vec<String> = self.idrefs.iter().filter(|r| !self.ids.contains(*r)).cloned().collect();
        for r in missing {
            self.error(|| format!("IDREF '{r}' has no matching ID"));
        }
    }
}

fn validate(bytes: &[u8], verbose: bool) -> (usize, Vec<String>) {
    let mut v = Validator::new(verbose);
    match std::str::from_utf8(bytes) {
        Ok(text) => v.run(text),
        Err(_) => v.error(|| "not UTF-8".into()),
    }
    (v.errors, v.messages.unwrap_or_default())
}

/// Baseline: the same quick-xml pass (events + attribute values), no validation.
fn parse_only(bytes: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(bytes) else { return 1 };
    let mut reader = Reader::from_str(text);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                for a in e.attributes() {
                    let Ok(a) = a else { return 1 };
                    if a.normalized_value_with(XmlVersion::Implicit1_0, 1, |_| Some("")).is_err() {
                        return 1;
                    }
                }
            }
            Ok(Event::Eof) => return 0,
            Err(_) => return 1,
            _ => {}
        }
    }
}

fn main() {
    let nthreads: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(1);
    let verbose = std::env::var_os("VERBOSE").is_some();
    let parse_only_mode = std::env::var_os("PARSE_ONLY").is_some();
    let files: Vec<String> = io::stdin().lock().lines().map(Result::unwrap).collect();
    let next = AtomicUsize::new(0);
    let (bytes, invalid, errors) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..nthreads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= files.len() {
                    break;
                }
                let data = std::fs::read(&files[i]).unwrap();
                bytes.fetch_add(data.len(), Ordering::Relaxed);
                let (n, msgs) = if parse_only_mode { (parse_only(&data), vec![]) } else { validate(&data, verbose) };
                if n > 0 {
                    invalid.fetch_add(1, Ordering::Relaxed);
                    errors.fetch_add(n, Ordering::Relaxed);
                    println!("INVALID {} {}", files[i], n);
                    for m in msgs {
                        println!("  {m}");
                    }
                }
            });
        }
    });
    let secs = t0.elapsed().as_secs_f64();
    let b = bytes.into_inner();
    println!(
        "validator={} threads={nthreads} files={} bytes={b} invalid_files={} errors={} \
         dtd_load_s=0.000 seconds={secs:.3} files_per_s={:.0} MB_per_s={:.1}",
        if parse_only_mode { "parse-only-rust" } else { "compiled-rust" },
        files.len(),
        invalid.into_inner(),
        errors.into_inner(),
        files.len() as f64 / secs,
        b as f64 / secs / 1e6
    );
}
