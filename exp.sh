#!/bin/sh
LD_LIBRARY_PATH=external/libneo4j-client-v4-install/lib/ ./gentree -d data/pguess_metrics_cache.tsv data/rockyou.sortedfreq.txt rules/primitives.rule $1 $2 $3 -w data/words.txt
sort -t$'\t' -r -n -k 2 results/passwords_analysis.tsv -o results/passwords_analysis_sorted.tsv
cut -d$'\t' -f1 results/passwords_analysis_sorted.tsv > results/passwords_sorted.txt
sort -t$'\t' -r -n -k 2 results/rules_analysis.tsv -o results/rules_analysis_sorted.tsv
echo ':' > results/generated.rule
cut -d$'\t' -f1 results/rules_analysis_sorted.tsv >> results/generated.rule
head -n 10000 results/generated.rule > results/generated.10k.rule
head -n 50000 results/generated.rule > results/generated.50k.rule

