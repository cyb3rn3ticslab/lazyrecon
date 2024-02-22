#!/bin/bash

ITERATOR=0
BAR='##############################'
FILL='------------------------------'
totalLines=$(wc -l "$2" | awk '{print $1}')  # num. lines in file
barLen=30
count=0

# --- iterate over lines in file ---
sensor(){
    while read line; do
        # update progress bar
        count=$(($count + 1))
        percent=$((($count * 100 / $totalLines * 100) / 100))
        i=$(($percent * $barLen / 100))
        echo -ne "\r[${BAR:0:$i}${FILL:$i:barLen}] $count/$totalLines ($percent%)"
        eval "$1" > 
    done < "$2"
}

sensor "$@"