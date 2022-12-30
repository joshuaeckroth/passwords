#!/bin/sh
LD_LIBRARY_PATH=external/libneo4j-client-v4-install/lib/ ./gentree data/rockyou-train-100k.txt rules/primitives.rule $1 $2 /usr/share/dict/words
rm -rf ~/.local/share/hashcat ; hashcat -m 0 -a 0 -r results/generated.rule hashed/rockyou-test-1mil.md5.txt data/rockyou-train-100k.txt  | grep 'Recovered\.'

