cut -f 2 -d ':' $1 | awk '{sum+=$1} END {print "Sum: ", sum}'
