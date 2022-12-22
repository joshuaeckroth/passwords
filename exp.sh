#!/bin/sh
LD_LIBRARY_PATH=external/libneo4j-client-v4-install/lib/ ./gentree data/rockyou-shuf-train-100k.txt rules/primitives.rule $1 $2
rm -rf ~/.local/share/hashcat ; hashcat -m 0 -a 0 -r results/generated.rule hashed/rockyou-shuf-test-100k-small.md5.txt data/rockyou-shuf-train-100k.txt  | grep 'Recovered\.'

