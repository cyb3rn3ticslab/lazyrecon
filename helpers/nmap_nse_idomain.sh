#!/bin/bash

nmap_nse(){
  # https://gist.github.com/storenth/b419dc17d2168257b37aa075b7dd3399
  # https://youtu.be/La3iWKRX-tE?t=1200
  # https://medium.com/@noobhax/my-recon-process-dns-enumeration-d0e288f81a8a
  echo "$[nmap] scanning..."
    IP=$1

    echo "[nmap] scanning $IP..."
    # -Pn: Treat all hosts as online - skip host discovery
    # -n: no DNS resolution
    # -sV: Probe open ports to determine service/version info (--version-intensity 9: means maximum probes)
    # -sS: raw packages
    # -sC: equivalent to --script=default (-O and -sC equal to run with -A)
    # -T4: aggressive time scanning
    # --spoof-mac Cisco: Spoofs the MAC address to match a Cisco product
    nmap -vv --spoof-mac 0 -n -sC -sV --version-intensity 9 -sS -Pn -T4 $IP
    echo
}

nmap_nse $1