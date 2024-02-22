#!/bin/bash

# ../nuclei-templates/vulnerabilities/generic/ 
# -t ../nuclei-templates/cves/2020/
# -t ../nuclei-templates/exposed-panels/ \
# -t ../nuclei-templates/misconfiguration/ \
# fuzzing/iis-shortname.yaml
# fuzzing/wp-plugin-scan.yaml
  # exposures/configs/git-config.yaml
        # -t ../nuclei-templates/fuzzing/ 
        # -exclude ../nuclei-templates/fuzzing/basic-auth-bruteforce.yaml
        # -exclude ../nuclei-templates/fuzzing/wp-plugin-scan.yaml
nucleitest(){
  echo "$[nuclei] scanning..."
  # echo "[nmap] scanning $line for technologies"
  # nuclei -silent -l $1 -t ../nuclei-templates/technologies/
  # sleep 1
  echo "[nmap] scanning $line for potential vulns"
  nuclei -silent -stats -l $1 -t ../nuclei-templates/exposures/configs/
  echo
  echo
}

nucleitest $1