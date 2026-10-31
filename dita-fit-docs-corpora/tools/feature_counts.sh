#!/usr/bin/env bash
# Count Learn-Markdown / DocFX feature usage in a checked-out MicrosoftDocs repo.
# usage: tools/feature_counts.sh REPO_DIR   (sparse checkout of *.md *.yml *.json is enough)
# Output: TSV  feature  files  occurrences
set -uo pipefail
R=${1:?repo dir}
c(){ # name regex [glob]
  local g=${3:-*.md}
  printf '%s\t%s\t%s\n' "$1" \
    "$(git -C "$R" grep -l -I -E -e "$2" -- "$g" | wc -l)" \
    "$(git -C "$R" grep -o -I -E -e "$2" -- "$g" | wc -l)"; }
c include                 '\[!INCLUDE'
c include-inline          '[^ >].*\[!INCLUDE \['
c include-cross-repo      '\[!INCLUDE[^]]*\]\(~/\.\./'
c alert                   '\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]'
c moniker-inline          '^::: *moniker range'
c monikerRange-frontmatter '^monikerRange:'
c moniker-range-operator  'onikerRange?[:=] *["'"'"']?[^"'"'"']*(>=|<=|>|<|\|\|)'
c zone-pivot              '^::: *zone pivot'
c zone-target             '^::: *zone target'
c zone_pivot_groups-fm    '^zone_pivot_groups:'
c tab-heading             '\]\(#tab/'
c tab-nested              '\]\(#tab/[^)/]+/[^)]+\)'
c code-triple-colon       ':::code '
c code-range              ':::code [^:]*range='
c code-id                 ':::code [^:]*\bid='
c code-highlight          ':::code [^:]*highlight='
c code-legacy             '\[!code-[a-z]+\['
c code-interactive        'interactive="cloudshell'
c fence-interactive       '^ *```[a-z]+-interactive'
c fence-syntaxsql         '^ *```syntaxsql'
c fence-mermaid           '^ *```mermaid'
c image-triple-colon      ':::image '
c image-complex           ':::image [^:]*type="complex"'
c image-icon              ':::image [^:]*type="icon"'
c image-lightbox          ':::image [^:]*lightbox='
c image-border            ':::image [^:]*border="false"'
c image-locscope          ':::image [^:]*loc-scope='
c video                   '(:::video |\[!VIDEO )'
c row-column              '^ *:::(row|column)'
c div-nextstepaction      '\[!div class="nextstepaction"\]'
c div-checklist           '\[!div class="checklist"\]'
c div-op_single_selector  '\[!div class="op_single_selector'
c no-loc-inline           ':::no-loc '
c no-loc-fm               '^no-loc:'
c xref                    '(<xref:|\(xref:)'
c xref-displayProperty    'xref:[^>)]*displayProperty='
c tilde-root-link         '\]\(~/'
c html-a-name             '<a name='
c html-kbd                '<kbd>'
c html-br-in-table        '^\|.*<br ?/?>'
c html-details            '<details>'
c appliesto-include       '\[!INCLUDE \[[^]]*applies'
c uid-fm                  '^uid:'
c ms.topic                '^ms\.topic:'
c ms.service              '^ms\.service:'
c ms.subservice           '^ms\.subservice:'
c ms.custom               '^ms\.custom:'
c ms.collection           '^ms\.collection:'
c ms.devlang              '^ms\.devlang:'
c ms.reviewer             '^ms\.reviewer:'
c titleSuffix             '^titleSuffix:'
c robots-noindex          '^ *(ROBOTS|robots): *NOINDEX'
c helpviewer_keywords     '^helpviewer_keywords:'
c f1_keywords             '^f1_keywords:'
c dev_langs               '^dev_langs:'
c YamlMime-any            '^### YamlMime:'                 '*.yml'
c YamlMime-Landing        '^### YamlMime:Landing'          '*.yml'
c YamlMime-Hub            '^### YamlMime:Hub'              '*.yml'
c YamlMime-FAQ            '^### YamlMime:FAQ'              '*.yml'
c toc-displayName         '^ *displayName:'                ':(icase)*toc.yml'
c toc-expanded            '^ *expanded: *true'             ':(icase)*toc.yml'
c toc-nested-tocref       'href: *[^ ]*toc\.yml'           ':(icase)*toc.yml'
c toc-topicHref           '^ *(topicHref|tocHref):'        ':(icase)*toc.yml'
c toc-items               '^ *- *name:'                    ':(icase)*toc.yml'
c breadcrumb-files        'tocHref:'                       ':(icase)*breadcrumb*.yml'
printf 'redirect-entries\t-\t%s\n' "$(git -C "$R" grep -o -I -E '"source_path(_from_root)?"' -- '*.redirection*.json' '.openpublishing.redirection*.json' | wc -l)"
printf 'redirect_document_id-true\t-\t%s\n' "$(git -C "$R" grep -o -I -E '"redirect_document_id": *true' -- '*.json' | wc -l)"
printf 'toc.yml-files\t%s\t-\n' "$(git -C "$R" ls-files '*toc.yml' | wc -l)"
printf 'docfx.json-files\t%s\t-\n' "$(git -C "$R" ls-files '*docfx.json' | wc -l)"
printf 'zone-pivot-groups.yml\t%s\t-\n' "$(git -C "$R" ls-files '*zone-pivot-groups.yml' | wc -l)"
printf 'markdownlint-config\t%s\t-\n' "$(git -C "$R" ls-files '*.markdownlint*' | wc -l)"
printf 'md-files\t%s\t-\n' "$(git -C "$R" ls-files '*.md' | wc -l)"
