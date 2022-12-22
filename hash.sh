#!/bin/sh

while read -r line; do
    echo -n $line | md5sum | sed 's/ -.*//g'
done
