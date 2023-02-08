#!/bin/bash

# Produces a "# cracked / # attempted" graph where the y-axis is the ratio the x-axis is the number attempted where
# the number attempted is a proxy for time.  Each rulefile has a color coded line.  Script runs hashcat on provided
# "top-n" rules generated by our program and on rules we want to compare against (ex: dive, best64, etc.).  Script
# writes results to tsv files which are then read by a python script that uses matplotlib to produce the graphs.
# hashcat defaults to using md5 and device 1 and a reporting interval of 1s

RED='\033[0;31m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
RESET='\033[0m'

PYTHON=python3

if [ $# -lt 5 ]; then
    echo -e "Usage: ./cracked_attempted.sh ${RED}[path/to/hashed]${RESET} ${CYAN}[path/to/dict]${RESET} ${GREEN}[path/to/generated/rules]${RESET} ${YELLOW}[csv integers of top-n rules to try]${RESET} [path/to/results] ${MAGENTA}<csv paths to additional rulefiles>${RESET} ${BLUE}<hashcat hash type> <hashcat device> <hashcat reporting interval (s)>${RESET}"
    echo -e "Ex: ./cracked_attempted.sh ${RED}hashed/rockyou-test-1mil.md5.txt${RESET} ${CYAN}data/rockyou-train-100k.txt${RESET} ${GREEN}results/analyze_results.tsv${RESET} ${YELLOW}100,1000,10000${RESET} results ${MAGENTA}rules/best64.rule,rules/dive.rule${RESET}"
    exit 1
fi

HC_HASH=${7:-0}
HC_DEVICE=${8:-1}
HC_REPORT_INTERVAL=${9:-1}
echo -e "Hashcat hash mode:" $HC_HASH
echo -e "Hashcat device:" $HC_DEVICE

HASHED=$1
WORDS=$2
RDIR=$5
TOP_NS=($(awk -F',' '{for (i=1; i<=NF; i++) print $i}' <<< "$4"))
RESULTS_SORTED=$RDIR/analyze_results_sorted.tsv
POTFILE_DIR=~/.local/share/hashcat
TOP_N_PATHS=""
TOP_N_RULECOUNTS=""
COMPARISON_PATHS=""
COMPARISON_RULE_COUNTS=""

sort -k 2n $3 > $RESULTS_SORTED
echo "Running hashcat with generated rulefiles"

for i in "${TOP_NS[@]}"
do
    echo "Running hashcat for top" $i "generated rules"
    TOP_N=$RDIR/results_top_$i.rule
    TOP_N_STATUS=$RDIR/hc_status_top_$i.txt
    TOP_N_RECOVERED=$RDIR/hc_status_recovered_top_$i.txt
    TOP_N_PROGRESS=$RDIR/hc_status_progress_top_$i.txt
    TOP_N_STARTED=$RDIR/hc_status_started_top_$i.txt
    TOP_N_DATA=$RDIR/hc_data_generated_top_$i.tsv
    if [ ! -e $TOP_N_STATUS ]
    then
        echo ":" > $TOP_N
        cat $RESULTS_SORTED | cut -f1 | duprule/target/debug/duprule | tail -n $i >> $TOP_N
        rm -rf $POTFILE_DIR
        hashcat --session=$BASHPID --potfile-disable -O --status --status-timer=$HC_REPORT_INTERVAL -d $HC_DEVICE -m $HC_HASH -a 0 -r $TOP_N $HASHED $WORDS | grep '\(Recovered\.\.\.\|Progress\.\.\.\)' > $TOP_N_STATUS
    fi
    cat $TOP_N_STATUS | grep -Eo 'Recovered\.+: ([0-9]+)' | awk '{print $2}' > $TOP_N_RECOVERED
    cat $TOP_N_STATUS | grep -Eo 'Progress\.+: ([0-9]+)' | awk '{print $2}' > $TOP_N_PROGRESS
    ## cat $TOP_N_STATUS | grep Started > $TOP_N_STARTED
    echo -e "0\t0" > $TOP_N_DATA
    paste $TOP_N_RECOVERED $TOP_N_PROGRESS >> $TOP_N_DATA
    TOP_N_PATHS+="${TOP_N_DATA},"
    TOP_N_RULECOUNTS+="${i},"
done

# TOP_N_PATHS is csv separated paths of result files to send to python, strip last comma
TOP_N_PATHS=$(sed 's/.\{1\}$//' <<< "$TOP_N_PATHS")
TOP_N_RULECOUNTS=$(sed 's/.\{1\}$//' <<< "$TOP_N_RULECOUNTS")

if [ $# -gt 5 ]; then
    echo "Running hashcat with additional comparison rulefiles"
    COMP_RULEFILES=($(awk -F',' '{for (i=1; i<=NF; i++) print $i}' <<< "$6"))
    for RULEFILE in "${COMP_RULEFILES[@]}"
    do
        echo "Running hashcat for additional rulefile" $RULEFILE
        RULEFILE_NAME=$(echo $RULEFILE | rev | cut -d '/' -f 1 | rev | sed 's/\.[^.]*$//')
        # echo "RULEFILE_NAME is: " $RULEFILE_NAME
        ADDITIONAL_STATUS=$RDIR/hc_status_$RULEFILE_NAME.txt
        ADDITIONAL_RECOVERED=$RDIR/hc_status_recovered_$RULEFILE_NAME.txt
        ADDITIONAL_PROGRESS=$RDIR/hc_status_progress_$RULEFILE_NAME.txt
        ADDITIONAL_STARTED=$RDIR/hc_status_started_$RULEFILE_NAME.txt
        ADDITIONAL_DATA=$RDIR/hc_data_$RULEFILE_NAME.tsv
        if [ ! -e $ADDITIONAL_STATUS ]
        then
            rm -rf $POTFILE_DIR
            hashcat --session=$BASHPID --potfile-disable -O --status --status-timer=$HC_REPORT_INTERVAL -d $HC_DEVICE -m $HC_HASH -a 0 -r $RULEFILE $HASHED $WORDS | grep '\(Recovered\.\.\.\|Progress\.\.\.\)' > $ADDITIONAL_STATUS
        fi
        cat $ADDITIONAL_STATUS | grep -Eo 'Recovered\.+: ([0-9]+)' | awk '{print $2}' > $ADDITIONAL_RECOVERED
        cat $ADDITIONAL_STATUS | grep -Eo 'Progress\.+: ([0-9]+)' | awk '{print $2}' > $ADDITIONAL_PROGRESS
        ## cat $ADDITIONAL_STATUS | grep Started > $ADDITIONAL_STARTED
        echo -e "0\t0" > $ADDITIONAL_DATA
        paste $ADDITIONAL_RECOVERED $ADDITIONAL_PROGRESS >> $ADDITIONAL_DATA
        COMPARISON_PATHS+="${ADDITIONAL_DATA},"
        COMPARISON_RULE_COUNTS+="$(wc -l $RULEFILE | awk '{print $1}'),"
    done
    COMPARISON_PATHS=$(sed 's/.\{1\}$//' <<< $COMPARISON_PATHS)
    COMPARISON_RULE_COUNTS=$(sed 's/.\{1\}$//' <<< $COMPARISON_RULE_COUNTS)
fi
HASHED_FNAME=$(echo $HASHED | rev | cut -d '/' -f 1 | rev)
WORDS_FNAME=$(echo $WORDS | rev | cut -d '/' -f 1 | rev)
$PYTHON cracked_attempted.py $TOP_N_PATHS $TOP_N_RULECOUNTS $COMPARISON_PATHS $COMPARISON_RULE_COUNTS $HASHED_FNAME $WORDS_FNAME

