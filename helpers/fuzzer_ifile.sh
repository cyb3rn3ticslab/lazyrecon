#!/bin/bash

# input masscan_output file
fuzz(){
  while read line; do
    IP=$(echo $line | awk '{ print $4 }')
    PORT=$(echo $line | awk -F '[/ ]+' '{print $7}')
    echo "[cat /dev/random] fuzzing $IP using $PORT port"

    cat /dev/random |  nc -zv $IP $PORT
    echo
  done < $1
}

fuzz $1
