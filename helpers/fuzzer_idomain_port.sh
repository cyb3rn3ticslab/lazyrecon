#!/bin/bash

fuzz(){
    cat /dev/random |  nc -vv $1 $2
}

fuzz "$@"
