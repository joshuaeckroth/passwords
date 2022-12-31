#!/bin/bash
if [ $# -gt 4 ]; then
    echo "Usage: ./analyze.sh [path/to/hashed] [path/to/dict] [comma separated top-n generated rules] [comma separates paths to additional rule files]"
    echo "Ex: ./analyze.sh hashed/rockyou-test-1mil.md5.txt data/rockyou-train-100k.txt 10,50,64,100,1000 rules/best64.rule,rules/dive.rule"
    exit 1
fi
RDIR=results
sort -k 2n $RDIR/analyze_results.tsv > $RDIR/analyze_results_sorted.tsv
#pcts=()
idx=0
echo "Running hashcat with generated rulefiles"
top_ns=()
IFS=',' read -r -a top_ns <<< $3
hashed=$1
words=$2
for i in "${top_ns[@]}"
do
    head -n $i $RDIR/analyze_results_sorted.tsv | cut -f1 > $RDIR/results_top_$i.rule
    rm -rf ~/.local/share/hashcat
    rec_pct=$(hashcat -m 0 -a 0 -r $RDIR/results_top_$i.rule $hashed $words | grep 'Recovered\.' | grep -Eo '[0-9]+\.[0-9]+')
    echo "For top $i cracked $rec_pct%"
    echo "$idx,generated $i,$rec_pct" >> $RDIR/plot.csv
    #pcts+=($rec_pct)
    let idx=idx+1
done
echo "Running hashcat with comparison rulefiles"
if [ $# -gt 3 ]; then
    comparison_rulefiles=($(awk -F',' '{for (i=1; i<=NF; i++) print $i}' <<< "$4"))
    for rulefile in "${comparison_rulefiles[@]}"
    do
        rec_pct_2=$(hashcat -m 0 -a 0 -r $rulefile $hashed $words | grep 'Recovered\.' | grep -Eo '[0-9]+\.[0-9]+')
	echo "For $rulefile cracked $rec_pct_2"
        echo "$idx,$rulefile,$rec_pct_2" >> $RDIR/plot.csv
        let idx=idx+1
    done
fi
gnuplot -persist <<-EOFMarker
    set title "RULESET EFFICACY"
    set terminal png
    set output "graph.png"
    set yrange [0:100]
    set pointsize 1
    set datafile separator ","
    set boxwidth 0.5
    set style fill solid
    set ylabel "Percentage cracked"
    set xlabel "Ruleset
    plot "$RDIR/plot.csv" using 1:3:xtic(2) with boxes
EOFMarker
echo "Done!"
