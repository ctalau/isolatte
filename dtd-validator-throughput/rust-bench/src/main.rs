//! DTD-validate DITA topics with a pure-Rust validator, parsing each
//! (flattened) DTD once per thread.
//!
//! usage: rust-bench xmloxide|rusty_xml THREADS MAPFILE < file-list
//!   MAPFILE lines: PUBLIC-ID<TAB>flattened.dtd

use std::io::{self, BufRead};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};
use std::time::Instant;

/// One loaded DTD per DOCTYPE public id, in map-file order.
enum Dtds {
    Xmloxide(Vec<xmloxide::validation::dtd::Dtd>),
    RustyXml(Vec<rusty_xml::XmlDtd>),
}

fn load(which: &str, paths: &[String]) -> Dtds {
    let texts: Vec<String> = paths.iter().map(|p| std::fs::read_to_string(p).unwrap()).collect();
    match which {
        "xmloxide" => Dtds::Xmloxide(
            texts
                .iter()
                .map(|t| xmloxide::validation::dtd::parse_dtd(t).expect("xmloxide: DTD parse"))
                .collect(),
        ),
        "rusty_xml" => Dtds::RustyXml(
            texts
                .iter()
                .map(|t| rusty_xml::xml_parse_dtd(t.as_bytes(), None, None).expect("rusty_xml: DTD parse"))
                .collect(),
        ),
        _ => panic!("unknown validator {which}"),
    }
}

/// The PUBLIC id of the DOCTYPE, read straight from the bytes.
fn doctype_public_id(bytes: &[u8]) -> Option<&str> {
    let head = &bytes[..bytes.len().min(2048)];
    let text = std::str::from_utf8(head).ok()?;
    let rest = &text[text.find("<!DOCTYPE")?..];
    let rest = &rest[rest.find("PUBLIC")? + 6..];
    let open = rest.find('"')? + 1;
    let close = open + rest[open..].find('"')?;
    Some(&rest[open..close])
}

/// Returns the number of validity / well-formedness errors (0 = valid).
fn validate(dtds: &Dtds, publics: &[String], bytes: &[u8]) -> usize {
    let Some(idx) = doctype_public_id(bytes).and_then(|p| publics.iter().position(|x| x == p)) else {
        return 1;
    };
    match dtds {
        Dtds::Xmloxide(d) => {
            let Ok(text) = std::str::from_utf8(bytes) else { return 1 };
            match xmloxide::Document::parse_str(text) {
                Ok(mut doc) => {
                    let result = xmloxide::validation::dtd::validate(&mut doc, &d[idx]);
                    if std::env::var_os("VERBOSE").is_some() {
                        for e in &result.errors {
                            eprintln!("  {e}");
                        }
                    }
                    result.errors.len()
                }
                Err(_) => 1,
            }
        }
        Dtds::RustyXml(d) => {
            let opts = rusty_xml::XML_PARSE_NONET | rusty_xml::XML_PARSE_NOERROR | rusty_xml::XML_PARSE_NOWARNING;
            match rusty_xml::xml_read_memory(bytes, None, None, opts) {
                Ok(doc) => rusty_xml::xml_validate_dtd(&doc, &d[idx]).map_or(1, |_| 0),
                Err(_) => 1,
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: {} xmloxide|rusty_xml THREADS MAPFILE < files", args[0]);
        std::process::exit(2);
    }
    let which = args[1].as_str();
    let nthreads: usize = args[2].parse().unwrap();
    let (mut publics, mut paths) = (Vec::new(), Vec::new());
    for line in std::fs::read_to_string(&args[3]).unwrap().lines() {
        if let Some((p, f)) = line.split_once('\t') {
            publics.push(p.to_string());
            paths.push(f.to_string());
        }
    }
    let files: Vec<String> = io::stdin().lock().lines().map(Result::unwrap).collect();

    let next = AtomicUsize::new(0);
    let (bytes, invalid, errors) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let barrier = Barrier::new(nthreads);
    let loaded_at = Mutex::new(None);
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..nthreads {
            s.spawn(|| {
                let dtds = load(which, &paths);
                // Wait until every thread has its DTDs so validation is timed alone.
                if barrier.wait().is_leader() {
                    *loaded_at.lock().unwrap() = Some(Instant::now());
                }
                barrier.wait();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= files.len() {
                        break;
                    }
                    let data = std::fs::read(&files[i]).unwrap();
                    bytes.fetch_add(data.len(), Ordering::Relaxed);
                    let n = validate(&dtds, &publics, &data);
                    if n > 0 {
                        invalid.fetch_add(1, Ordering::Relaxed);
                        errors.fetch_add(n, Ordering::Relaxed);
                        println!("INVALID {} {}", files[i], n);
                    }
                }
            });
        }
    });
    let loaded = loaded_at.into_inner().unwrap().unwrap();
    let load_s = (loaded - t0).as_secs_f64();
    let secs = loaded.elapsed().as_secs_f64();
    let b = bytes.into_inner();
    println!(
        "validator={which} threads={nthreads} files={} bytes={b} invalid_files={} errors={} \
         dtd_load_s={load_s:.3} seconds={secs:.3} files_per_s={:.0} MB_per_s={:.1}",
        files.len(),
        invalid.into_inner(),
        errors.into_inner(),
        files.len() as f64 / secs,
        b as f64 / secs / 1e6
    );
}
