#!/bin/sh
LD_LIBRARY_PATH=external/libneo4j-client-v4-install/lib/ ./gentree data/rockyou-train-100k.txt rules/primitives.rule $1 $2 data/english-words-by-frequency/wikipedia_words.trimmed.100k.txt
rm -rf ~/.local/share/hashcat ; hashcat -m 0 -a 0 -r results/generated.rule hashed/rockyou-test-1mil.md5.txt data/rockyou-train-100k.txt  | grep 'Recovered\.'

