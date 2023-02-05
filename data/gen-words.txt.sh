#!/bin/sh
sed 's/[^a-zA-Z]//g' rockyou.txt | perl -ne 'print unless $seen{$_}++' > rockyou-words.txt
paste -d '\n' english-words-by-frequency/wikipedia_words.trimmed.txt rockyou-words.txt | perl -ne 'print unless $seen{$_}++' > words.txt
