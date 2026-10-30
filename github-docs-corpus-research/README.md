# Large public GitHub documentation corpora

Snapshot: 30 October 2026. Counts are based on Git trees and histories inspected during this research, not live totals. [repositories.csv](repositories.csv) records the selected repositories, commit IDs, current counts, and completed history counts. The samples are not rankings of all GitHub repositories.

## Findings

| Corpus | Scope | Current documentation-format paths | Historical documentation paths | Current translation paths |
|---|---|---:|---:|---:|
| Microsoft Docs sample | 193 public MicrosoftDocs repositories returned by a repository search for `docs`; two were empty | 395,352 | At least 1,102,624 in 11 scanned histories | At least 657 identified by locale directories |
| Azure-named subset | 22 repositories in the Microsoft sample whose names start with `azure` | 65,090 | At least 817,775 in four scanned histories | Not reliably determined |
| MDN content | [mdn/content](https://github.com/mdn/content/tree/15d531b54c7f0d96ac80ef00b494fd40743d59ce) and [mdn/translated-content](https://github.com/mdn/translated-content/tree/033e5bf0a0ed3d4203313a5079bc95e054df7aa6) | 52,431 | 76,785 in both default-branch histories | 37,600 in translation content directories |
| AWS guide sample | 248 public awsdocs repositories returned by a repository search for `guide` | 4,956 | At least 13,147 in six scanned histories | Not reliably determined |

The Azure subset is included in the Microsoft sample; do not add the two totals. The Microsoft and AWS samples are search-selected subsets, not comprehensive counts of their organizations or published sites. The history lower bounds are sums over only the repositories with completed scans in the CSV; a path in two repositories is counted twice. The million-path result is historical, not a claim that a million files exist at once.

AWS [retired most public documentation repositories in 2023](https://aws.amazon.com/blogs/aws/retiring-the-aws-documentation-on-github/); many default branches no longer contain the full former guide. The AWS current count is therefore not a measure of the documentation on the live AWS website. The Azure core repository's full history did not finish downloading and is not included in the historical lower bound.

## Largest individual Microsoft repositories in the sample

The following links pin the sampled commits. A dash means the measure was not completed; it is not a zero.

| Repository | Current documentation paths | Historical paths | Translation paths |
|---|---:|---:|---:|
| [VBA-Docs](https://github.com/MicrosoftDocs/VBA-Docs/tree/b202c96d9d53) | 38,187 | 155,845 | — |
| [webview2-win32-reference](https://github.com/MicrosoftDocs/webview2-win32-reference/tree/38bc5e980832) | 29,316 | — | — |
| [microsoftgraph-docs-powershell](https://github.com/MicrosoftDocs/microsoftgraph-docs-powershell/tree/ee4ec05b3c95) | 27,432 | — | — |
| [azure-docs-powershell](https://github.com/MicrosoftDocs/azure-docs-powershell/tree/5bb303bc9996) | 27,194 | 806,654 | — |
| [windows-driver-docs-ddi](https://github.com/MicrosoftDocs/windows-driver-docs-ddi/tree/7515063cea4c) | 25,913 | 27,932 | — |
| [azure-docs](https://github.com/MicrosoftDocs/azure-docs/tree/434a5dc3adb3) | 16,755 | — | — |
| [sql-docs](https://github.com/MicrosoftDocs/sql-docs/tree/e357e15f4a4b) | 14,470 | 41,869 | — |
| [windows-driver-docs](https://github.com/MicrosoftDocs/windows-driver-docs/tree/b1f6aa5c1275) | 14,412 | — | — |
| [windows-powershell-docs](https://github.com/MicrosoftDocs/windows-powershell-docs/tree/b7645dd8c687) | 14,158 | — | — |
| [webview2-winrt-reference](https://github.com/MicrosoftDocs/webview2-winrt-reference/tree/452730b9d3bb) | 13,723 | — | — |

Other measured examples: [.NET docs](https://github.com/dotnet/docs/tree/faf8e5d14b5f) had 13,986 current and 25,038 historical paths. [Kubernetes website](https://github.com/kubernetes/website/tree/43374c571c6f) had 8,349 current and 22,257 historical paths, including 5,812 current paths under non-English content directories.

## MDN translation breakdown

The current translated-content tree contains 37,674 matching files in total, including 37,600 under `files/` locale directories. The remaining 74 include repository support documents. The locale content counts are:

| Locale directory | Current documentation paths |
|---|---:|
| `ja` | 10,315 |
| `fr` | 7,865 |
| `zh-cn` | 7,617 |
| `ko` | 3,345 |
| `ru` | 2,787 |
| `es` | 2,645 |
| `pt-br` | 2,015 |
| `zh-tw` | 1,011 |
| **Total** | **37,600** |

MDN describes the [separate translation repository](https://developer.mozilla.org/en-US/docs/MDN/Community/Translated_content); counting a locale path does not establish that its content is current or a complete translation of an English page.

## Method and limits

- **Current count:** recursively list the selected commit's Git tree and count paths ending in `.md`, `.markdown`, `.mdx`, `.dita`, `.ditamap`, `.rst`, `.adoc`, or `.asciidoc`, case-insensitively. This includes support documents, reusable fragments, translations, and generated reference files. YAML, HTML, XML with other extensions, and other formats are excluded. It is not a count of distinct published pages or unique content.
- **History count:** for each completed scan, list changed paths over all commits reachable from the sampled default-branch commit, including merge diffs and root commits, disable rename detection, deduplicate paths within the repository, and apply the same extension filter. A rename can count as two paths; repeated revisions at one path count once. Other branch-only histories and tags not reachable from that commit are excluded. The aggregate is a sum across repositories, not cross-repository deduplication.
- **Translations:** translation paths are already included in current counts. For MDN, the count covers matching files under the translated repository's `files/` directory. For Kubernetes, the count covers matching files in non-`en` directories under `content/`. For Microsoft, the minimum reflects matching files under recognized locale-named path components; it is not a comprehensive language classification. AWS was not classified.
- **Reproduction:** for a checked-out repository with full default-branch history, replace `COMMIT` with the CSV's commit. The history command can be expensive and needs adequate temporary disk space.

```sh
git ls-tree -r --name-only COMMIT |
  awk 'tolower($0) ~ /\.(md|markdown|mdx|dita|ditamap|rst|adoc|asciidoc)$/ {n++} END {print n+0}'

git log -m --root COMMIT --pretty=format: --name-only --no-renames |
  LC_ALL=C sort -u |
  awk 'tolower($0) ~ /\.(md|markdown|mdx|dita|ditamap|rst|adoc|asciidoc)$/ {n++} END {print n+0}'
```

Git's quoted path output and unusual filenames can affect a line-based count. For a rigorous follow-up, use NUL-delimited output, capture the complete search result and errors, classify formats and locales explicitly, and scan all intended refs. Large history counts may reflect generated or versioned API-reference trees, so inspect paths before using them as a proxy for independent documents.
