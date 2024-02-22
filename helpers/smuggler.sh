#!/bin/bash

DIRNAMEPATH=$(dirname "${1}")
# https://github.com/gwen001/pentest-tools/blob/master/smuggler.py
smugglertest(){
  echo "[smuggler.py] Try to find request smuggling vulns..."
  smuggler -u "$1"

  # check for VULNURABLE keyword
  if [ -s $DIRNAMEPATH/smuggler/output ]; then
    grep 'VULNERABLE' ./smuggler/output > $DIRNAMEPATH/smugglinghosts.txt
    if [ -s $DIRNAMEPATH/smugglinghosts.txt ]; then
      echo "Smuggling vulnerability found under the next hosts:"
      echo
      grep 'VULN' $DIRNAMEPATH/smugglinghosts.txt
    else
      echo "There are no Request Smuggling host found"
    fi
  else
    echo "smuggler doesn\'t provide the output, check it issue!"
  fi
}
smuggler "$1"
