#!/bin/bash

./cracked_attempted.sh hashed/pwned-passwords-sha1-ordered-by-count-v8.top10mil.txt data/rockyou.sortedfreq.1mil.txt results/rules_analysis.tsv 250000 results rules/best64.rule,rules/dive.rule,rules/pantagrule.one.royce.rule 100 2
