#!/bin/sh
rm -rf ~/.local/share/hashcat ; hashcat --status -d 1 -m 100 -a 0 -r $1 hashed/pwned-passwords-sha1-ordered-by-count-v8.top1mil.txt data/rockyou.sortedfreq.100k.txt  | grep '\(Recovered\.\.\.\|Progress\.\.\.\|Time\.Estimated\|Time\.Started\)'
