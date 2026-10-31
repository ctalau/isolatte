#!/usr/bin/env bash
# Reproduce the measurements in README.md.
# usage: ./run.sh WORK_DIR      (needs git, python3 with lxml; ~1 GB of disk)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${1:?work dir}
mkdir -p "$WORK/facts" "$WORK/results"
cd "$WORK"

# repo  commit  docset-root-for-~/
PINS='
MicrosoftDocs/sql-docs              75b38454ce9c88d8ce43365be0adca39f577cddf docs
MicrosoftDocs/azure-docs            84ce263e4a1bdd0ce29cb5afde8ae98d1ad4068f .
awsdocs/amazon-aurora-user-guide      7a931b460fab44aa012879002cf8c0e1a2a1d70e .
awsdocs/amazon-ec2-user-guide         e3707c431483ec0ffffcabebd36cf799ba682cd0 .
awsdocs/amazon-rds-user-guide         f2e9ed35fba2cb7e3942a1c23ed5b37162222d41 .
awsdocs/amazon-s3-developer-guide     ede850670797468806c93177d73bbdcb0b7a6913 .
awsdocs/aws-cloudformation-user-guide 19dc52cd3f2007d6d268b65b739ffb5ebf8c1e76 .
awsdocs/aws-lambda-developer-guide    03f7fcb0b771f031f7cb3aa43e8b18407c00b3a8 .
awsdocs/iam-user-guide                e2b8637a825b9f292bb04af61277d067dfcc5676 .
'
# AWS commits are the parents of the 2023 "delete content directory" commits.

echo "$PINS" | while read -r slug commit root; do
  [ -z "$slug" ] && continue
  name=${slug#*/}
  if [ ! -d "$name" ]; then
    git clone -q --filter=blob:none --no-checkout "https://github.com/$slug.git" "$name"
    git -C "$name" sparse-checkout set --no-cone '/**/*.md' '/**/*.yml' '/**/*.json'
    git -C "$name" checkout -q "$commit"
  fi
  python3 -I "$HERE/tools/extract.py" "$name" "$commit" "facts/$name.xml" "$root"
  python3 -I "$HERE/tools/run.py" "$HERE/tools/rules.sch" "facts/$name.xml" > "results/$name.tsv"
  echo "== $name"; cut -c1-160 "results/$name.tsv"
done

# Reuse/variant counts for the two Microsoft repositories (README table 1).
for r in sql-docs azure-docs; do
  echo "== reuse signals: $r"
  c(){ printf '%-22s files=%-6s occurrences=%s\n' "$1" \
        "$(git -C $r grep -l -E "$2" -- '*.md' | wc -l)" "$(git -C $r grep -o -E "$2" -- '*.md' | wc -l)"; }
  c INCLUDE        '\[!INCLUDE'
  c moniker-inline '::: *moniker range'
  c monikerRange   '^monikerRange:'
  c zone-pivot     '::: *zone pivot'
  c tabs           '\]\(#tab/'
  c code-ref       ':::code '
  c xref           '<xref:|\(xref:'
  c alerts         '\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]'
  c nextstepaction 'nextstepaction'
done

# RDS vs Aurora verbatim overlap (README AWS section).
L(){ git -C "$1" ls-files -z '*.md' | (cd "$1" && xargs -0 awk 'length($0)>100 && $0 !~ /^(#|\|)/') |
     sed 's/<a name="[^"]*"><\/a>//g' | sort -u; }
L amazon-rds-user-guide > rds.lines; L amazon-aurora-user-guide > aurora.lines
echo "RDS unique long lines: $(wc -l < rds.lines); Aurora: $(wc -l < aurora.lines); shared: $(comm -12 rds.lines aurora.lines | wc -l)"
