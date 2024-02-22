#!/bin/bash
# Script creates HTML report
# invokation: ./report.sh "my.games" "/Users/kali/zi-targets/my.games/recon-21-04-18_23-16-43"


# Variables
TITLE="Powered by cyb3rn3ticslab"
TARGETDIR=$2
CURRENT_TIME=$(date +"%x %r %Z")
TIME_STAMP="Generated $CURRENT_TIME, by $USER"
INVOKATION=$(cat ${TARGETDIR}/_call_params.txt)
PUBLICIP=$(curl -s https://api.ipify.org)

# Images
images() {
    echo '<div>'
    for line in ${TARGETDIR}/screenshots/*; do
        # remove http(s) and .png file extension
        FILENAME=$(basename $line | sed -E 's/https?-//;s/[.]png//')
        # replace - with : if line contains a port
        # HERE
        URLWITHPORT=$(echo ${FILENAME} | grep -E "\-[[:digit:]]{2,}$")
        if [ -n "${URLWITHPORT}" ]; then
            URL=$(echo ${URLWITHPORT} | sed -E 's/^(.*)-/\1\:/')
        else
            URL=${FILENAME}
        fi

        echo "<p><a href=${URL}>${URL}</a></p>"
        echo "<img src=${line} width=400px height=auto alt=${URL}>"
        # get nuclei's output
        if [ -s ${TARGETDIR}/tmp/nuclei_technology_out.txt ]; then
        technote="$(grep ${URL} ${TARGETDIR}/tmp/nuclei_technology_out.txt | cut -d ' ' -f 3,5,6 | awk '{ print $2 $1" "$3}')"
            for tech in $technote; do
                echo "<p style='color: #404040; font-size: 10px;'>${tech}</p>"
            done
        fi
        if [ -s $TARGETDIR/nuclei/nuclei_out.txt ]; then
            techissue="$(grep ${URL} $TARGETDIR/nuclei/nuclei_out.txt | cut -d ' ' -f 3,5,6 | awk '{ print $2 $1" "$3}')"
            for issue in $techissue; do
                echo "<p style='color: #AD3F60; font-size: 10px;'>${issue}</p>"
            done
        fi
    done
    echo '</div>'
}

openports(){
    # add open ports
    if [ -s ${TARGETDIR}/naabu_out ]; then
        echo '<div>'
            echo "<h4>Open ports found:</h4>"
            ports=$(cat $TARGETDIR/naabu_out)
            echo "<pre style='font-size: 10px;'><code>""${ports}""</code></pre>"
        echo '</div>'
    else
        echo "<h3>There are no open ports found.</h3>"
    fi
}

listenserverlogs(){
    # add listen server logs
    if [ -s ${TARGETDIR}/_listen_server_out.log ]; then
        echo "<h4>Listen server out</h4>"
        srvlogs=$(< $TARGETDIR/_listen_server_out.log jq -r '.protocol,."remote-address",."raw-request"' | grep -A 11 -F "http")
        echo "<pre style='font-size: 9px;'><code>""${srvlogs}""</code></pre>"
    fi
}

# Main entry point
echo "<!DOCTYPE html>
<HTML lang=en>
<HEAD>
<meta charset="UTF-8"> 
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<TITLE>$TITLE</TITLE>
</HEAD>
<BODY>
<p>Powered by $ 1a3y.sh with the next parameters: $INVOKATION</p>
<p>$TIME_STAMP</p>
<p>Public IP=$PUBLICIP</p>
<H1>Security report for $1</H1>
"

openports
images
listenserverlogs

echo "</BODY>
</HTML>
"
