#!/bin/bash

# https://github.com/tomnomnom/gf/issues/55
filter(){
    echo
    echo "json=$1"
    echo "file=$2"
    echo "output=$3"

    gf $1 $2 | uniq > $3
}

filter "$@"