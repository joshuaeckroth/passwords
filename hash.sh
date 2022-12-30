#!/bin/sh

cat $1 | pv -l | perl -MDigest::MD5=md5_hex -nlE'say md5_hex($_)'

