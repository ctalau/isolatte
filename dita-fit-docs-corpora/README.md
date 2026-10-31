# Would Microsoft/Azure and AWS docs benefit from DITA?

The question: if the Microsoft Learn (including Azure) and AWS documentation corpora described in
[`github-docs-corpus-research`](../github-docs-corpus-research/README.md) were converted to DITA,
would they be a complex DITA scenario (profiling, reuse, conrefs)? Which advanced DITA features would
really help? And would Schematron help?

Short answer:

- **sql-docs** is a real DITA-shaped problem. It has very heavy reuse, product names reused as
  variables, and filtering by product × version.
- **azure-docs** has a lot of reuse, but most of its variation is *reader-side* (language pivots
  and tabs that the reader switches). DITA handles that badly.
- **AWS** is a single-source, multi-guide corpus: RDS and Aurora share 46% of their prose. But the
  public Markdown is a *generated export* of AWS's internal XML source, so the real source is not
  visible.
- **Schematron** works on these corpora and finds real defects (§3). For Microsoft, though, most of
  what it catches is already caught, or could be caught, by DocFX build checks and linters.

## Corpora and pinned commits

Each repository was cloned shallow or blob-less with sparse checkout (`.md`, `.yml`, `.json` only).
The AWS commits are the last commits before the 2023 "delete content directory" commits.

| Repository | Commit | Date | `.md` files |
|---|---|---|---:|
| MicrosoftDocs/sql-docs | `75b38454ce9c` | 2026-10-30 | 14,472 |
| MicrosoftDocs/azure-docs | `84ce263e4a1b` | 2026-10-31 | 16,761 |
| awsdocs/aws-cloudformation-user-guide | `19dc52cd3f20` | 2023-12-07 | 7,204 |
| awsdocs/amazon-aurora-user-guide | `7a931b460fab` | 2023-06-15 | 905 |
| awsdocs/amazon-rds-user-guide | `f2e9ed35fba2` | 2023-06-15 | 672 |
| awsdocs/amazon-ec2-user-guide (Linux) | `e3707c431483` | 2023-06-15 | 557 |
| awsdocs/iam-user-guide | `e2b8637a825b` | 2023-06-15 | 406 |
| awsdocs/aws-lambda-developer-guide | `03f7fcb0b771` | 2023-10-30 | 400 |
| awsdocs/amazon-s3-developer-guide | `ede850670797` | 2020-11-04 | 396 |

`./run.sh WORK_DIR` re-clones these and reproduces every number below. It needs `git`, `python3`
and `lxml`, and about 1 GB of disk.

## 1. Reuse and variant signals

### Microsoft

| Signal | sql-docs | azure-docs |
|---|---:|---:|
| Files using `[!INCLUDE]` / include calls | 12,205 (84%) / **72,597** | 6,112 / 13,976 |
| Include files / ones ≤300 bytes (really text variables) | 852 / **305** | 1,519 / 78 |
| Includes that include other files | 306 | 252 |
| Includes containing moniker/zone conditions | 5 | 4 |
| `monikerRange` (version filter) metadata on whole files | **3,508** | 25 |
| Inline `::: moniker range` blocks, in files | 1,001, in 189 files | 137, in 41 files |
| `::: zone pivot` blocks (reader-side switch), in files | 496, in 31 files | **6,029, in 703 files** |
| Tabs (`#tab/`) | 1,624 | **17,589** |
| "Applies to" include calls | 10,933 | 719 |
| `<xref:>` links by ID | 5,138 | 0 |
| Redirect entries (all redirection files) | 15,403 | 23,961 |
| Long prose lines pasted verbatim into ≥10 non-include files | 97 lines, 2,464 copies | 115 lines, 2,860 copies |

Telling details:

- `docs/includes/ssnoversion-md.md` contains the words "SQL Server" and nothing else. It is
  included **23,272 times**.
- sql-docs version filters use *ranges*, e.g.
  `=azuresqldb-current || >=sql-server-2017 || >=sql-server-linux-2017 || =azuresqldb-mi-current || =fabric-sqldb`
  (632 files use exactly this expression).
- In azure-docs, "An Azure account with an active subscription…" is pasted by hand into 278 files,
  even though an include exists for it.

### AWS

**The GitHub Markdown is generated, not authored.** Evidence:

- every `.` is escaped as `\.`;
- every heading carries a generated `<a name>` anchor;
- *none* of the 29,632 code blocks has a language tag;
- the EC2 export contains zero images.

AWS's real source is internal XML, so its reuse mechanisms (entities, XIncludes, conditions,
whatever they are) were flattened away before publication. What remains visible is the *effect* of
reuse:

| Signal | Value |
|---|---:|
| RDS unique long prose lines also present verbatim in the Aurora guide | **6,491 of 14,001 (46%)** |
| Files with the same name in both RDS and Aurora / byte-identical | 451 / 65 |
| CloudFormation "*Update requires*: No interruption" / "Replacement" lines | 5,851 / 1,638 |
| CloudFormation boilerplate on `Ref` / `Fn::GetAtt` | 771 / 606 |
| RDS "Sign in to the AWS Management Console and open the Amazon RDS console…" step | 140 |
| Absolute `docs.aws.amazon.com` links across the 7 guides | **50,962** (37,354 in CloudFormation) |
| RDS file names that are specific to a database engine (Oracle / SQL Server / MySQL / PostgreSQL / MariaDB) | 76 / 45 / 40 / 30 / 22 |

How to read this:

- RDS and Aurora behave like two profiled outputs of one source.
- The engine-specific chapters are a natural `@platform`-style filtering axis.
- CloudFormation's 7,204 files are mostly reference pages generated from resource schemas.

I could not clone the EC2 Windows guide: the clone asked for credentials, so the repository is
probably deleted or private. The Linux/Windows split therefore could not be measured.

## 2. Fifty advanced DITA features, assessed

**H** = would really help · **M** = some help, with caveats · **L** = little help ·
**✗** = DITA does not solve the actual problem · **?** = can't tell from public data

| # | Feature | MS (sql / azure) | AWS | Honest assessment |
|---:|---|:-:|:-:|---|
| 1 | conref (reuse an element by reference) | H / M | H? | Maps one-to-one onto 72.6k + 14k include calls, and allows reuse of single elements. DocFX includes already do most of this. AWS's 46% RDS/Aurora overlap says reuse is needed, but its XML source probably already does it. |
| 2 | conkeyref | H / M | H? | The same topic pulls a different fragment per deliverable (SQL Server vs Managed Instance; RDS vs Aurora). DocFX has no equivalent. |
| 3 | conrefend (reuse a range of elements) | M | M | Reuse a run of steps. Many of the 2,371 Microsoft include files exist only because an include must be a whole file. |
| 4 | conaction push/mark | L | L | Confusing semantics; rarely successful at scale. |
| 5 | keyref text variables | **H** / M | M | 305 tiny include files and 23k+ calls are poor man's variables. Renames (Azure AD → Entra ID: 1,392 stale mentions still found; Elasticsearch → OpenSearch: 8 in AWS) are exactly what keys fix. |
| 6 | keyref on links | H / H | **H** | ~39k Microsoft redirects show path churn, and 5,714 Microsoft links work only *through* a redirect (§3). AWS: 51k absolute self-links. Keys decouple links from paths. External URL redirects are still needed. |
| 7 | Key scopes | H / L | H | sql-docs: one topic, different product name/port/edition per deliverable. AWS: RDS vs Aurora. |
| 8 | Shared key-definition maps | M | M | Product names cut across repositories (sql/azure/fabric; all AWS guides). Needs governance across organizations. |
| 9 | Cross-deliverable links (peer maps, DITA 1.3) | M | H | AWS guides link each other constantly. The model is right, but DITA-OT support is weak; expect custom work. |
| 10 | Reusing a topic in several maps | M | M | `toc.yml` can already point at a file twice. Useful for RDS/Aurora shared chapters. |
| 11 | Submaps (`mapref`) | M | M | 293 `toc.yml` files at Microsoft (33 in sql-docs, 260 in azure-docs). Modest gain. |
| 12 | copy-to | M | M | Same source under different URLs with different keys. Duplicate pages hurt search ranking. |
| 13 | Reuse-warehouse topics | H (discipline) | ? | Would absorb the ~5.3k hand-pasted copies. Honest caveat: those copies exist because authors ignored existing includes. That is a people problem. |
| 14 | coderef / code from line ranges | M | M | 2.2k `:::code` uses at Microsoft (318 sql-docs + 1,878 azure-docs); AWS pulls from aws-doc-sdk-examples. DocFX already does regions; roughly parity. |
| 15 | @product/@platform filtering via DITAVAL | **H** / L | H | Maps to 3,508 file-level and 1,001 inline monikers, and to the AWS database engines. **DITA has no range operators**: `>=sql-server-2017` must be expanded and updated every release. |
| 16 | Subject scheme maps | H | M | Controlled values for monikers, `ms.topic`, `ms.service`, engines. A hierarchy (sql-server › 2017/2019/2022/2025) lets one DITAVAL rule hit a whole group, which partly makes up for the missing ranges. |
| 17 | Specialized profiling attributes | M-H | M | `@sqlversion`/`@deployment`/`@engine` are clearer than overloading @product. |
| 18 | @deliveryTarget (DITA 2.0) | L | L | Mostly web output. |
| 19 | Branch filtering (`ditavalref`) | **H** / L | H | One map → SQL Server 2019/2022/2025, Azure SQL DB, Managed Instance; or one map → RDS + Aurora. This is the moniker build. |
| 20 | Flagging | M | L | Could generate the 10.9k hand-placed "applies to" banners. Styling needs custom output work. |
| 21 | Grouped values syntax `product(sql(2019 2022))` | M | M | Tidier; tool support uneven. |
| 22 | DITAVAL `passthrough` | L / M-H | L | Writes attributes into the HTML for client-side switching (6,029 zones, 17,589 tabs). The only standard hook for reader-side variants; the switching UI is all custom. |
| 23 | Filtering whole topics out of maps | H / L | M | Equals the per-file `monikerRange`. |
| 24 | @audience persona filtering | L | L | Both split audiences by article, not by filter. |
| 25 | @rev revision flagging | L | L | Git and release-notes pages cover it. |
| 26 | @status | L | L | |
| 27 | Task topics | M-H | M-H | Huge numbers of how-tos; step reuse and validation. Automatic conversion from free-form Markdown will misclassify a lot. |
| 28 | Concept/reference topics | M | M | `ms.topic` already classifies articles. |
| 29 | API/cmdlet reference specializations | L | L | Reference is generated (PowerShell help, mdoc, CloudFormation schemas). Keep generating; DITA is just another output. |
| 30 | Troubleshooting topic | M | M | Consistent structure for many troubleshooting pages. |
| 31 | Glossary / abbreviated-form (expand an acronym on first use) | M | M | Acronym expansion is not systematic in either. |
| 32 | Software/UI/programming domains | M | M | "Select **Create** > **Resource**" could be checked against UI strings. Authors won't tag consistently. |
| 33 | Custom specializations for tabs, pivots, "next step" blocks | ✗ | L | DITA has none of these, so you rebuild DocFX's Markdown extensions in XML just to stay even. |
| 34 | Constraint modules | L-M | L-M | Lock down content models per content set. |
| 35 | `<note type>` | L | L | One-to-one with ~35k alerts; no new value. |
| 36 | Image keyref, required alt text | M | ? | ~34k `:::image` uses. Missing alt text: **0 found**, because the Microsoft build already enforces it. |
| 37 | Long descriptions for complex images (`longdescref`) | L | L | Only 65 complex images. |
| 38 | Metadata cascading from maps | M | L | Removes repeated `ms.service`/author. DocFX `fileMetadata` already does this. |
| 39 | Learning & Training specialization | L | L | Training lives in separate YAML/LMS systems. |
| 40 | Relationship tables (reltables) | M | M | ~2.9k "next step" links. Large teams find reltables hard to maintain. |
| 41 | @collection-type sequence | M | M | Automatic previous/next for tutorial series. |
| 42 | @chunk | L | L | Only matters for PDF or combined pages. |
| 43 | Index terms | L | L | Readers arrive from web search. |
| 44 | Classification domain | M | M | Search facets; `ms.service` already plays this role. |
| 45 | @translate="no" | M | ? | Microsoft already has `:::no-loc:::`. |
| 46 | Translation savings from key/conref reuse | M-H | ? | Fragments translated once; machine-translation segment reuse narrows the gain. |
| 47 | Build-time integrity checks (DITA-OT + Schematron) | H | M | See §3: real defects exist, but the build already catches the worst classes. |
| 48 | Multiple output formats | L-M | L | Both sites already offer PDF. |
| 49 | Lightweight DITA Markdown authoring (LwDITA / MDITA) | **H (necessity)** | n/a | Microsoft's public contributors write Markdown pull requests. MDITA cannot express conref, keyscopes or most profiling, so the advanced features push authors back to XML. AWS stopped taking public contributions in 2023, so this is irrelevant there. |
| 50 | DITA 2.0 `<include>`, wider keyref | M | M | Cleaner text/code inclusion; tooling still maturing. |

About 12 features really help: 1, 2, 5, 6, 7, 13, 15, 16, 19, 23, 47, 49.

- At Microsoft, almost all of the gain lands on sql-docs-style content.
- At AWS, the gain lands on link keys and on single-sourcing RDS/Aurora. AWS already authors in
  XML, so DITA is a smaller step for them, but also a smaller *gain* over what they already have.

## 3. Would Schematron help? (measured)

Schematron validates XML, and these corpora are Markdown. So `tools/extract.py` parses each
repository into one "facts" XML document. Python only parses and resolves paths; **every decision
is made by ISO Schematron rules** (`tools/rules.sch`), run with lxml's XSLT 1.0 Schematron
implementation (`tools/run.py`).

What the extractor puts into the facts document:

- the whole Git tree, so file-existence checks cover images even though they were not checked out;
- every redirection file;
- every `zone-pivot-groups.yml`;
- Microsoft's `~/` paths (relative to the docset root), resolved per docset;
- references into dependent repositories (`reusable-content`, sample repositories), marked as
  not checkable.

Links inside code blocks are ignored.

| Rule | sql-docs | azure-docs | AWS (7 guides) |
|---|---:|---:|---:|
| R01 include target missing | 0 | 66 in 63 files | n/a |
| R02 relative link target missing **and** not redirected | 8 in 2 files | 259 in 193 files | 134 in 27 files |
| R04 image file missing | 0 | 62 in 26 files | 0 |
| R13 path differs from the real file only in letter case | **352** in 83 files | **396** in 150 files | 0 |
| R05 zone pivot not declared in its pivot group | 5 in 3 files | **235** in 32 files | n/a |
| R07 `ms.topic` outside controlled list | 7 | 51 (`Include` vs `include`, …) | n/a |
| R08 malformed `ms.date` | 1 | 3 | n/a |
| R06 required metadata missing (non-include topics) | 0 | 0 | n/a |
| R03 image without alt text | 0 | 0 | 0 |
| R09 heading level skipped (e.g. H2→H4) | 3,005 in 2,627 files | 1,957 in 988 files | 358 |
| R10 code block without language | 5,381 of 30,265 | 3,933 of 67,407 | **29,632 of 29,632** |
| R11 duplicate anchor in a file | 4 | 17 | 81 |
| R12 retired product name in text | 442 in 167 files | 950 in 428 files | 13 (8 real) |
| I04 link works only through a redirect | 818 in 445 files | **4,896** in 2,259 files | n/a |
| I03 reference into a dependent repo (unchecked) | 190 | 2,490 | n/a |
| I01 `ms.date` older than 3 years | 7,473 | 3,274 | n/a |
| Validation time (one aggregated document) | 58 s | 87 s | 78 s for CloudFormation, ≤3 s for the others |

### What this shows

- **Schematron can do this job.** It handles cross-file rules (via `xsl:key` over the file list,
  redirects and pivot groups), controlled vocabularies, co-occurrence rules and terminology. These
  are the things a DTD or RNG schema can't express, and the rule file is ~90 declarative lines.
- **The hard failures are few, because the Microsoft build already enforces them.** There are zero
  missing includes in sql-docs, zero missing alt text and zero missing required metadata. Remaining
  hard failures are a few hundred per repository.
- **The useful finds are the "soft" classes nobody blocks on:**
  - 748 case-only path mismatches: they work today only because resolution is case-insensitive
    somewhere, and they break on a case-sensitive host;
  - 5,714 links that depend on redirects (technical debt behind the ~39k redirect entries);
  - 240 pivots used but not declared in their group;
  - 1,392 mentions of "Azure Active Directory"/"Azure AD" two years after the rename to Entra ID;
  - heading skips, which are an accessibility problem.
- **For AWS, the public data is the wrong place to apply it.** The findings are mostly artefacts of
  the generator (no code languages, duplicate anchors, relative links to other guides missing their
  leading `/`). Schematron fits AWS's *real* XML source well, but that source isn't public.

### Precision caveats

- I did not run DocFX to confirm each hit.
- Spot checks:
  - 1 of 3 sampled R01 hits was clearly broken.
  - The other 2 were includes-inside-includes whose path is written relative to the outer topic.
    DocFX may resolve those differently, so R01/R02 are upper bounds for that pattern.
  - R12 also counts legitimate historical mentions ("formerly Azure AD").
  - R05 groups could in principle be declared in a dependent repository.
- The `ms.topic` "controlled list" is a proxy: values used ≥5 times across the two repositories,
  not Microsoft's official taxonomy.
- An early version of the extractor had large false-positive classes (cross-repo `~/` paths,
  regexes inside code blocks, redirect files using `source_path_from_root`, trailing spaces in
  image sources). Those were fixed before the numbers above were produced.

### Verdict on Schematron

- **Microsoft: M.** It's a good fit for a nightly cross-file quality report:
  - terminology after product renames;
  - controlled taxonomy values;
  - pivot/moniker declarations;
  - case and redirect hygiene.

  It is not essential: the same checks could be written as markdownlint/DocFX rules without an XML
  step. It only becomes **H** after a real DITA conversion. Then:

  - it works directly on the source;
  - Oxygen's Schematron Quick Fixes (SQF) can auto-fix renames, case mismatches and missing code
    languages in the editor;
  - it can check things DITA-OT does not, such as "an inline moniker must be a subset of the
    topic's `monikerRange`" or "every `<keyword keyref>` for a product must use a key from the
    subject scheme".
- **AWS: H for their internal XML pipeline, L for anything you can do with the public export.**
- **Performance:** single-threaded XSLT 1.0 over one 40–46 MB document is fine for nightly runs but
  too slow per pull request. Running Saxon/XSLT 3 per changed file plus a small shared index would
  be needed for pull-request checks.

## What worked, what did not, what next

**Worked:**

- Pinned shallow/sparse clones of the 2 Microsoft and 7 AWS repositories.
- Reuse/variant counts from grep.
- RDS/Aurora overlap measurement.
- A real ISO Schematron pass over ~41k Markdown files through an extracted facts layer, with
  false positives reduced by resolving docsets, dependent repositories and redirects.

**Did not work / not done:**

- The EC2 Windows guide could not be cloned.
- AWS's real source format is not public, so AWS reuse is inferred from duplication, not observed.
- Only 2 of the 193 Microsoft repositories were measured.
- Hits were not confirmed by running DocFX.
- No actual DITA conversion was attempted.
- The duplicate-line metric only catches exact lines over 100–150 characters.

**Next:**

1. Run `run.sh`-style extraction over all 193 Microsoft repositories.
2. Convert one sql-docs area to a DITA map with branch-filtered DITAVALs and measure how many
   moniker ranges explode into value lists.
3. Port `rules.sch` to Saxon/XSLT 3 with per-file validation to measure pull-request latency.
4. Add the moniker-subset rule.

**Opinion:**

- Converting Microsoft docs to DITA would technically work but would not pay off overall.
- sql-docs alone is the one place where DITA's key/profiling model clearly beats what exists. The
  missing range operators are the main design flaw to solve there.
- A hybrid is the realistic path: keep Markdown, add a key map, a subject scheme for monikers, and
  Schematron-style cross-file checks. That captures most of features 5, 6, 16 and 47.
- AWS already has the XML pipeline DITA would give them, so a DITA move there would be a tooling
  change, not a capability change.
