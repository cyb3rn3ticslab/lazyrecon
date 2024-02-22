#!/bin/bash

# input masscan_output file
getsingles(){
  while read line; do
    IP=$(echo $line | awk '{ print $4 }')
    PORT=$(echo $line | awk -F '[/ ]+' '{print $7}')
    echo "[cat /dev/random] fuzzing $IP using $PORT port"

    cat /dev/random |  nc -vv $IP $PORT
    echo
  done < $1
}

getsingles $1
