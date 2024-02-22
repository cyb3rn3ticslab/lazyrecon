#!/bin/bash

nucleitest(){
  echo "$[nuclei] single domain scanning..."
  cat $1 | nuclei -silent -l $1 -t ../nuclei-templates/technologies/
  cat $1 | nuclei -silent -bulk-size 45 -c 25 -l $1 -t ../nuclei-templates/fuzzing/ -t ../nuclei-templates/technologies/s3-detect.yaml -t ../nuclei-templates/subdomain-takeover/ -t ../nuclei-templates/generic-detections/ -t ../nuclei-templates/vulnerabilities/ -t ../nuclei-templates/security-misconfiguration/ -t ../nuclei-templates/cves/ -t ../nuclei-templates/misc/ -t ../nuclei-templates/files/ -exclude ../nuclei-templates/misc/missing-csp.yaml -exclude ../nuclei-templates/misc/missing-x-frame-options.yaml -exclude ../nuclei-templates/misc/missing-hsts.yaml -exclude ../nuclei-templates/fuzzing/basic-auth-bruteforce.yaml
  echo
}

nucleitest $1
