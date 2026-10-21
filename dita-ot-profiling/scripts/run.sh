#!/bin/bash
# usage: run.sh name ditahome [extra args]
name=$1; home=$2; shift 2
rm -rf ../out/$name
s=$(date +%s.%N)
$home/bin/dita --input=DITA/UserManual.ditamap --format=dita --filter=DITA/ditaval/editor-sa.ditaval --output=../out/$name "$@" > ../$name.log 2>&1
e=$(date +%s.%N)
echo "$name wall=$(echo "$e - $s" | bc)s files=$(find ../out/$name -type f | wc -l) $(grep -c BUILD.SUCC ../$name.log)"
