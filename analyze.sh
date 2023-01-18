#!/bin/bash

./cracked_attempted.sh hashed/pwned-passwords-sha1-ordered-by-count-v8.top1mil.txt data/rockyou.sortedfreq.100k.txt results/analyze_results.tsv 64,1000,5000,10000 results rules/best64.rule,rules/dive.rule,rules/pantagrule.one.royce.10k.rule,primitives.rule
