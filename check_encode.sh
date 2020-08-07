#!/bin/bash
iconv --list | sed -e 's/\/\///g' | tr " " "\n" | while read encoding
do
    transcoded=$(head -n1 $1 | iconv -sc -f $encoding -t UTF-8 2>/dev/null )
    echo "$encoding : $transcoded"
done