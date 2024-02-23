#!/bin/bash
# ZoomInfo Recon Script
set -eE
set -m

export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$HOME/go/bin:$HOMEDIR/go/bin

# background PID's control
PID_SUBFINDER_FIRST=
PID_ASSETFINDER=
PID_GAU=
PID_WAYBACK=
SERVER_PID=
PID_SCREEN=
PID_NUCLEI=
PID_HTTPX=

# cerating the storage directory
[ -d "$STORAGEDIR" ] || mkdir -p $STORAGEDIR

# Use sed properly
SEDOPTION=(-i)
if [[ "$OSTYPE" == "darwin"* ]]; then
  SEDOPTION=(-i '')
fi


# optional positional arguments
single= # if just one target in scope
wildcard= # fight against multi-level wildcard DNS to avoid false-positive results while subdomain resolves
brute= # enable directory bruteforce
fuzz= # enable parameter fuzzing (listen server is automatically deployed using https://github.com/projectdiscovery/interactsh)
quiet= # quiet mode

# wordlists 
MINIRESOLVERS=./resolvers/mini_resolvers.txt
ALTDNSWORDLIST=./lazyWordLists/altdns_wordlist_uniq.txt
BRUTEDNSWORDLIST=./wordlist/six2dez_wordlist.txt
APIWORDLIST=./wordlist/api.txt
DIRSEARCHWORDLIST=./wordlist/directory-list-lowercase-2.3-big.txt
LFIPAYLOAD=./wordlist/lfi-payload.txt
PARAMSLIST=./wordlist/params-list.txt


HTTPXCALL="httpx -silent -no-color -random-agent -mc 200,201,202,203,206 -ports 80,81,88,300,443,444,591,593,832,981,1001,1010,1311,1099,2082,2095,2096,2443,2480,3000,3001,3128,3333,3443,4243,4443,4444,4567,4711,4712,4993,5000,5080,5104,5108,5280,5281,5443,5601,5800,6543,7000,7001,7396,7443,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10001,10080,10443,10250,11371,11443,11080,12080,12443,14080,14443,15080,15443,15672,16080,16443,17080,17443,17778,18080,18091,18092,18443,19080,19443,20080,20443,20720,21080,21443,22080,22443,23080,23443,24080,24443,25080,25443,26080,26443,27080,27443,27201,28080,26443,32000,55440,55672"
CHECKHTTPX2XX="httpx -silent -no-color -random-agent -mc 200,201,202"
# used in sed to cut
UNWANTEDPATHS='/[;]/d;/[.]css$/d;/[.]png$/d;/[.]svg$/d;/[.]jpg$/d;/[.]jpeg$/d;/[.]webp$/d;/[.]gif$/d;/[.]woff$/d;/[.]html$/d'
UNWANTEDQUERIES="/^$/d;/^[^h]/d;/[;]/d;/[.]css$/d;/[.]png$/d;/[.]svg$/d;/[.]jpg$/d;/[.]jpeg$/d;/[.]webp$/d;/[.]gif$/d;/[.]woff$/d;/[.]html$/d;/[()]/d;/[{}]/d;/[\`]/d;/[\']/d;/[$]/d"
JUICYFILETYPES="txt|log|yaml|env|gz|config|sql|xml|xlsx|doc|bak|old|src|jar|jsp|zip|tar"
CHROMIUM=chromium


# Subdomains Enumerations
enumeratesubdomains(){
  if [ "$single" = "1" ]; then
    echo $1 > $TARGETDIR/enumerated-subdomains.txt
  else
    echo "[$(date +%H:%M:%S)] Enumerating all known domains using:"

    # Passive subdomain enumeration
    echo "Using Subfinder..."
    subfinder -all -d $1 -silent -o $TARGETDIR/subfinder-list.txt &
    PID_SUBFINDER_FIRST=$!

    echo "Using Assetfinder..."
    assetfinder --subs-only $1 > $TARGETDIR/assetfinder-list.txt &
    PID_ASSETFINDER=$!

    echo "Using Github-subdomains.py..."
    github-subdomains -d $1 -t $GITHUBTOKEN | sed "s/^\.//;/error/d" | grep "[.]${1}" > $TARGETDIR/github-subdomains-list.txt || true

    echo "wait PID_SUBFINDER_FIRST $PID_SUBFINDER_FIRST and PID_ASSETFINDER $PID_ASSETFINDER"
    wait $PID_SUBFINDER_FIRST $PID_ASSETFINDER
    echo "PID_SUBFINDER_FIRST $PID_SUBFINDER_FIRST and PID_ASSETFINDER $PID_ASSETFINDER done."
    
    echo "amass..."
    amass enum --passive -log $TARGETDIR/amass_errors.log -d $1 -o $TARGETDIR/amass-list.txt

    SCOPE=$1

    grep "[.]${SCOPE}$" $TARGETDIR/assetfinder-list.txt | sort -u -o $TARGETDIR/assetfinder-list.txt
    # remove all lines start with *-asterix and out-of-scope domains
    sed "${SEDOPTION[@]}" '/^*/d' $TARGETDIR/assetfinder-list.txt
    # sort enumerated subdomains
    sort -u "$TARGETDIR"/subfinder-list.txt $TARGETDIR/assetfinder-list.txt "$TARGETDIR"/github-subdomains-list.txt -o "$TARGETDIR"/enumerated-subdomains.txt
    echo $1 >> "${TARGETDIR}/enumerated-subdomains.txt" 

    if [[ -s "$TARGETDIR"/enumerated-subdomains.txt ]]; then
      sed "${SEDOPTION[@]}" '/^[.]/d' $TARGETDIR/enumerated-subdomains.txt
      if [[ -n "$alt" ]]; then
        echo
        < $TARGETDIR/enumerated-subdomains.txt unfurl format %S | sort -u > $TARGETDIR/tmp/enumerated-subdomains-wordlist.txt
        sort -u $ALTDNSWORDLIST $TARGETDIR/tmp/enumerated-subdomains-wordlist.txt -o $CUSTOMSUBDOMAINSWORDLIST
      fi
    else 
      echo "No target was found!"
      error_handler
    fi
  fi
  echo "[$(date +%H:%M:%S)] enumeration done."
}

getgau(){
  echo "gau..."
  SUBS=""
  if [[ -n "$wildcard" ]]; then
    SUBS="--subs"
  fi
  # gau -subs mean include subdomains
  < $TARGETDIR/enumerated-subdomains.txt gau $SUBS | sort -u | grep -E "$2" | qsreplace -a > $TARGETDIR/tmp/gau_output.txt
  echo "gau done."
}

getwaybackurl(){
  echo "get utls using waybackurls..."
  < $TARGETDIR/enumerated-subdomains.txt waybackurls | sort -u | grep -E "$2" | qsreplace -a > $TARGETDIR/tmp/waybackurls_output.txt
  echo "waybackurls done."
}

getallurls(){
  echo "get all urls using getallurls..."
  < $TARGETDIR/enumerated-subdomains.txt getallurls | sort -u | grep -E "$2" | qsreplace -a > $TARGETDIR/tmp/getallurls_output.txt
  echo "getallurls done."
}

getgithubendpoints(){
  echo "github-endpoints.py..."
  github-endpoints -d $1 -t $GITHUBTOKEN | sort -u | grep -E "$2" | qsreplace -a > $TARGETDIR/tmp/github-endpoints_out.txt || true
  echo "github-endpoints done."
}

checkwaybackurls(){
  echo
  echo "[$(date +%H:%M:%S)] get wayback machine stuff..."
  GREPSCOPE=
  if [[ -n "$single" || -n "$wildcard" ]]; then
      GREPSCOPE="https?://(w{3}.)?[.]?$1"
  else
      GREPSCOPE="https?://(([[:alnum:][:punct:]]+)+)?[.]?$1"
  fi

  getgau $1 $GREPSCOPE &
  PID_GAU=$!

  getwaybackurl $1 $GREPSCOPE &
  PID_WAYBACK=$!

  getgithubendpoints $1 $GREPSCOPE

  wait $PID_GAU $PID_WAYBACK

   if [ ! -d "$TARGETDIR/wayback" ];then
      echo "Creating Base Folder Structure for $TARGETDIR/wayback"
      mkdir "$TARGETDIR/wayback"
   fi

  sort -u $TARGETDIR/tmp/gau_output.txt $TARGETDIR/tmp/waybackurls_output.txt $TARGETDIR/tmp/github-endpoints_out.txt -o $TARGETDIR/wayback/wayback_output.txt

  sed "${SEDOPTION[@]}" '/:80/d' $TARGETDIR/wayback/wayback_output.txt

  # need to get some extras subdomains
  < $TARGETDIR/wayback/wayback_output.txt unfurl --unique domains | sed '/web.archive.org/d;/*.${1}/d' > $TARGETDIR/wayback-subdomains-list.txt

  if [[ -n "$single" && -n "$wildcard" ]]; then
    # prepare target specific subdomains wordlist to gain more subdomains using --mad mode
    < $TARGETDIR/wayback/wayback_output.txt unfurl format %S | sort | uniq > $TARGETDIR/wayback-subdomains-wordlist.txt
    sort -u $CUSTOMSUBDOMAINSWORDLIST $TARGETDIR/wayback-subdomains-wordlist.txt -o $CUSTOMSUBDOMAINSWORDLIST
  fi
  echo "[$(date +%H:%M:%S)] wayback machine done."
}

sortsubdomains(){
  if [[ -n "$wildcard" ]]; then
    sort -u $TARGETDIR/enumerated-subdomains.txt $TARGETDIR/wayback-subdomains-list.txt -o $TARGETDIR/1-real-subdomains.txt
    cp $TARGETDIR/1-real-subdomains.txt $TARGETDIR/2-all-subdomains.txt
  fi
}

dnsbruteforcing(){
  if [[ -n "$wildcard" ]]; then
    echo "[$(date +%H:%M:%S)] puredns bruteforce..."
    puredns bruteforce $BRUTEDNSWORDLIST $1 -r $MINIRESOLVERS --wildcard-batch 500000 -l 500 --wildcard-tests 20 -q | tee $TARGETDIR/purebruteforce.txt >> $TARGETDIR/1-real-subdomains.txt
    sort -u $TARGETDIR/1-real-subdomains.txt -o $TARGETDIR/1-real-subdomains.txt
    echo "[$(date +%H:%M:%S)] puredns bruteforce done."
  fi
}

permutatesubdomains(){
  if [[ -n "$alt" && -n "$wildcard" ]]; then
    echo "[$(date +%H:%M:%S)] dnsgen..."
    dnsgen -f $TARGETDIR/1-real-subdomains.txt -w $CUSTOMSUBDOMAINSWORDLIST | tee $TARGETDIR/dnsgen_out.txt
    puredns resolve $TARGETDIR/dnsgen_out.txt -r $MINIRESOLVERS -q --wildcard-batch 500000 --wildcard-tests 20 -l 500 | tee $TARGETDIR/resolved_dnsgen_out.txt

    sort -u $TARGETDIR/1-real-subdomains.txt $TARGETDIR/resolved_dnsgen_out.txt -o $TARGETDIR/2-all-subdomains.txt
    echo "[$(date +%H:%M:%S)] dnsgen done"

    echo "[$(date +%H:%M:%S)] alterate.sh fuzz..."
    ./helpers/alterate.sh "$TARGETDIR/1-real-subdomains.txt" > $TARGETDIR/tmp/alterate_out.txt
    echo "[$(date +%H:%M:%S)] alterate.sh done"

    sort -u $TARGETDIR/1-real-subdomains.txt $TARGETDIR/tmp/alterate_out.txt -o $TARGETDIR/2-all-subdomains.txt
  fi
}

# check live subdomains
# wildcard check like: `dig @188.93.60.15 A,CNAME {test123,0000}.$domain +short`
# puredns/shuffledns uses for wildcard sieving because massdns can't
dnsprobing(){
  echo
  # check we test hostname or IP
  if [[ -n "$ip" ]]; then
    echo
    echo "[$(date +%H:%M:%S)] [dnsx] try to get PTR records"
    echo $1 > $TARGETDIR/dnsprobe_ip.txt
    echo $1 | dnsx -silent -ptr -resp-only -o $TARGETDIR/dnsprobe_subdomains.txt # also try to get subdomains
  elif [[ -n "$cidr" ]]; then
    echo "[$(date +%H:%M:%S)] [dnsx] try to get PTR records"
    cp  $TARGETDIR/enumerated-subdomains.txt $TARGETDIR/dnsprobe_ip.txt
    dnsx -silent -ptr -resp-only -r $MINIRESOLVERS -l $TARGETDIR/dnsprobe_ip.txt -o $TARGETDIR/dnsprobe_subdomains.txt # also try to get subdomains
  elif [[ -n "$single" ]]; then
    echo "[$(date +%H:%M:%S)] [dnsx] getting hostnames and its A records..."
    echo $1 | dnsx -silent -retry 2 -a -resp-only -o $TARGETDIR/dnsprobe_ip.txt
    echo $1 > $TARGETDIR/dnsprobe_subdomains.txt
  elif [[ -n "$list" ]]; then
      echo "[$(date +%H:%M:%S)] [massdns] probing and wildcard sieving..."
      puredns -r $MINIRESOLVERS resolve $TARGETDIR/enumerated-subdomains.txt --wildcard-batch 100000 -l 5000 -w $TARGETDIR/resolved-list.txt

      # # additional resolving because shuffledns/pureDNS missing IP on output
      echo "[$(date +%H:%M:%S)] [dnsx] getting hostnames and its A records..."     
      dnsx -silent -retry 2 -t 250 -a -resp -r $MINIRESOLVERS -l $TARGETDIR/resolved-list.txt -o $TARGETDIR/dnsprobe_out.txt

      # clear file from [ and ] symbols
      tr -d '\[\]' < $TARGETDIR/dnsprobe_out.txt > $TARGETDIR/dnsprobe_output_tmp.txt

      # split resolved hosts ans its IP (for masscan)
      cut -f1 -d ' ' $TARGETDIR/dnsprobe_output_tmp.txt | sort | uniq > $TARGETDIR/dnsprobe_subdomains.txt
      cut -f2 -d ' ' $TARGETDIR/dnsprobe_output_tmp.txt | sort | uniq > $TARGETDIR/dnsprobe_ip.txt
  else
      echo "[$(date +%H:%M:%S)] [puredns] massdns probing with wildcard sieving..."
      puredns -r $MINIRESOLVERS resolve $TARGETDIR/2-all-subdomains.txt --wildcard-batch 500000 -l 500 --wildcard-tests 20 -w $TARGETDIR/resolved-list.txt

      # additional resolving because shuffledns missing IP on output
      echo
      echo "[$(date +%H:%M:%S)] [dnsx] getting hostnames and its A records..."
      dnsx -silent -retry 2 -t 150 -a -resp -r $MINIRESOLVERS -l $TARGETDIR/resolved-list.txt -o $TARGETDIR/dnsprobe_out.txt

      # clear file from [ and ] symbols
      tr -d '\[\]' < $TARGETDIR/dnsprobe_out.txt | sed "/8.8.8.8/d;/1.1.1.1/d" > $TARGETDIR/dnsprobe_output_tmp.txt
      # split resolved hosts ans its IP (for masscan)
      cut -f1 -d ' ' $TARGETDIR/dnsprobe_output_tmp.txt | sort | uniq > $TARGETDIR/dnsprobe_subdomains.txt
      cut -f2 -d ' ' $TARGETDIR/dnsprobe_output_tmp.txt | sort | uniq > $TARGETDIR/dnsprobe_ip.txt
  fi
  echo "[$(date +%H:%M:%S)] [dnsx] done."
}

checkhttprobe(){
  echo
  echo "[$(date +%H:%M:%S)] [httpx] Starting http probe testing..."
  # resolve IP and hosts using socket address style for chromium, nuclei, gospider, ssrf, lfi and bruteforce
  if [[ -n "$ip" || -n "$cidr" || -n "$list" ]]; then
    echo "[httpx] IP probe testing..."
    $HTTPXCALL -status-code -l $TARGETDIR/dnsprobe_ip.txt -o $TARGETDIR/tmp/subdomain-live-status-code-scheme.txt
    $HTTPXCALL -status-code -l $TARGETDIR/dnsprobe_subdomains.txt >> $TARGETDIR/tmp/subdomain-live-status-code-scheme.txt
    cut -f1 -d ' ' $TARGETDIR/tmp/subdomain-live-status-code-scheme.txt >> $TARGETDIR/3-all-subdomain-live-scheme.txt
    grep -E "\[4([0-9]){2}\]" $TARGETDIR/tmp/subdomain-live-status-code-scheme.txt | cut -f1 -d ' ' > $TARGETDIR/4xx-all-subdomain-live-scheme.txt
  else
    echo "[httpx] Domain probe testing..."
    $CHECKHTTPX2XX -status-code -l $TARGETDIR/dnsprobe_subdomains.txt -o $TARGETDIR/tmp/subdomain-live-status-code-scheme.txt
    $CHECKHTTPX2XX -status-code -l $TARGETDIR/dnsprobe_ip.txt >> $TARGETDIR/tmp/subdomain-live-status-code-scheme.txt
    cut -f1 -d ' ' $TARGETDIR/tmp/subdomain-live-status-code-scheme.txt >> $TARGETDIR/3-all-subdomain-live-scheme.txt
    grep -E "\[4([0-9]){2}\]" $TARGETDIR/tmp/subdomain-live-status-code-scheme.txt | cut -f1 -d ' ' > $TARGETDIR/4xx-all-subdomain-live-scheme.txt
    if [[ -n "$alt" && -s "$TARGETDIR"/dnsprobe_ip.txt ]]; then
      echo
      echo "[$(date +%H:%M:%S)] [math Mode] finding math Mode of the IP numbers"
      ./helpers/modefinder.sh "$TARGETDIR/dnsprobe_ip.txt" 24  > $TARGETDIR/tmp/modefinder_out.txt

      if [[ -s $TARGETDIR/tmp/modefinder_out.txt ]]; then
        dnsx -silent -resp-only -ptr -retry 2 -r $MINIRESOLVERS -rl $REQUESTSPERSECOND -l $TARGETDIR/tmp/modefinder_out.txt -o $TARGETDIR/tmp/ptr_all_1.txt
        [[ -s "$TARGETDIR"/tmp/ptr_all_1.txt ]] && grep "$1" $TARGETDIR/tmp/ptr_all_1.txt | sort -u | tee $TARGETDIR/tmp/ptr_scope_2.txt \
          | puredns -q -r $MINIRESOLVERS resolve --skip-wildcard-filter | tee $TARGETDIR/tmp/ptr_resolved_3.txt \
          | dnsx -silent -r $MINIRESOLVERS -a -resp-only | tee -a $TARGETDIR/dnsprobe_ip.txt | tee $TARGETDIR/tmp/ptr_ip_4.txt

        [[ -s "$TARGETDIR"/tmp/ptr_ip_4.txt ]] && $HTTPXCALL -l $TARGETDIR/tmp/ptr_ip_4.txt -o $TARGETDIR/tmp/ptr_http_5.txt

        # sort new assets
        [[ -s "$TARGETDIR"/tmp/ptr_http_5.txt ]] && sort -u $TARGETDIR/tmp/ptr_http_5.txt $TARGETDIR/3-all-subdomain-live-scheme.txt -o $TARGETDIR/3-all-subdomain-live-scheme.txt
        sort -u $TARGETDIR/dnsprobe_ip.txt -o $TARGETDIR/dnsprobe_ip.txt

        #######################################
        # TEST all IP to verify scope visually
              echo "[$(date +%H:%M:%S)] [math Mode] TEST httpx probes of all finded Modes of IPs"
              $HTTPXCALL -l $TARGETDIR/tmp/modefinder_out.txt -o $TARGETDIR/http_modefinder_out.txt

              echo "$(date +%H:%M:%S)] secretfinder"
              mkdir -p $TARGETDIR/tmp/secretfinder/modefinder
              secretfinder -i $TARGETDIR/http_modefinder_out.txt -o $TARGETDIR/tmp/secretfinder/modefinder
              cat $TARGETDIR/tmp/secretfinder/modefinder/merge/* > $TARGETDIR/secretfinder_modefinder_out.txt
              echo "$(date +%H:%M:%S)] secretfinder done"
        #######################################

      fi
      echo "[$(date +%H:%M:%S)] [math Mode] done."
    fi
  fi
  echo "[$(date +%H:%M:%S)] [httpx] done."
}

bypass403test(){
  echo
  echo "[$(date +%H:%M:%S)] [bypass403] Try bypass 4xx..."
  if [ -s $TARGETDIR/4xx-all-subdomain-live-scheme.txt ]; then
    interlace --silent -tL "$TARGETDIR/4xx-all-subdomain-live-scheme.txt" -threads 50 -c "bypass-403 _target_ ''" | grep -E "\[2[0-9]{2}\]" | tee $TARGETDIR/4xx-bypass-output.txt
  fi
  echo "[$(date +%H:%M:%S)] [bypass403] done."
}

gospidertest(){
  if [ -s $TARGETDIR/3-all-subdomain-live-scheme.txt ]; then
    echo
    echo "[$(date +%H:%M:%S)] [gospider] Web crawling..."
    gospider -q --no-redirect -H "$CUSTOMHEADER" -S $TARGETDIR/3-all-subdomain-live-scheme.txt -o $TARGETDIR/gospider -t 2 1> /dev/null

    # combine the results and filter out of scope
    cat $TARGETDIR/gospider/* > $TARGETDIR/tmp/gospider_raw_out.txt

    # prepare paths list
    grep -e '\[form\]' -e '\[javascript\]' -e '\[linkfinder\]' -e '\[robots\]' -e '\[href\]' $TARGETDIR/tmp/gospider_raw_out.txt \
      | cut -f3 -d ' ' \
      | sort -u > $TARGETDIR/gospider/gospider_out.txt

    grep '\[url\]' $TARGETDIR/tmp/gospider_raw_out.txt | cut -f5 -d ' ' | sort -u >> $TARGETDIR/gospider/gospider_out.txt

    if [[  -z "$single" && -z "$list" ]]; then
      # extract domains
      < $TARGETDIR/gospider/gospider_out.txt unfurl --unique domains \
        | grep -E "(([[:alnum:][:punct:]]+)+)?[.]?$1" \
        | sort -u \
        | $HTTPXCALL \
        | tee $TARGETDIR/gospider-subdomain-live-scheme.txt

      [[ -s $TARGETDIR/gospider-subdomain-live-scheme.txt ]] && sort -u $TARGETDIR/3-all-subdomain-live-scheme.txt $TARGETDIR/gospider-subdomain-live-scheme.txt -o $TARGETDIR/3-all-subdomain-live-scheme.txt
    fi
    echo "[$(date +%H:%M:%S)] [gospider] done."
  fi
}

pagefetcher(){
  if [[ -s $TARGETDIR/3-all-subdomain-live-scheme.txt ]]; then
    SCOPE=$1
    echo
    # echo "[$(date +%H:%M:%S)] [page-fetch] Fetch page's DOM..."
    # < $TARGETDIR/3-all-subdomain-live-scheme.txt page-fetch --no-third-party --exclude image/ --exclude css/ -o $TARGETDIR/page-fetched 1> /dev/null
    # grep -horE "https?:[^\"\\'> ]+|www[.][^\"\\'> ]+" $TARGETDIR/page-fetched | sort -u > $TARGETDIR/page-fetched/pagefetcher_output.txt

    if [[ -z "$single" ]]; then
      # extract domains
      < $TARGETDIR/page-fetched/pagefetcher_output.txt unfurl --unique domains \
        | grep -E "(([[:alnum:][:punct:]]+)+)?[.]?$1" \
        | sort -u \
        | $HTTPXCALL \
        | tee $TARGETDIR/pagefetcher-subdomain-live-scheme.txt

      [[ -s $TARGETDIR/pagefetcher-subdomain-live-scheme.txt ]] && sort -u $TARGETDIR/3-all-subdomain-live-scheme.txt $TARGETDIR/pagefetcher-subdomain-live-scheme.txt -o $TARGETDIR/3-all-subdomain-live-scheme.txt
    fi
    echo "[$(date +%H:%M:%S)] [page-fetch] done."
  fi
}

screenshots(){
  if [ -s "$TARGETDIR"/3-all-subdomain-live-scheme.txt ]; then
    echo "[$(date +%H:%M:%S)] [screenshot] starts..."
    mkdir "$TARGETDIR"/screenshots   

    # Check if 3-all-subdomain-live-scheme.txt exists
    if [ ! -f "$TARGETDIR/3-all-subdomain-live-scheme.txt" ]; then
      echo "Error: 3-all-subdomain-live-scheme.txt file not found."
      exit 1
    fi

    # Read each line of 3-all-subdomain-live-scheme.txt and take screenshots
    while IFS= read -r subdomain; do
        if [ -n "$subdomain" ]; then
            echo "Capturing screenshot for: $subdomain"
            cutycapt --url="$subdomain" --out="$TARGETDIR/$(echo "$subdomain" | tr '/' '_').png"
        fi
    done < "$TARGETDIR/3-all-subdomain-live-scheme.txt"
    echo "[$(date +%H:%M:%S)] [Screenshots captured successfully] done."
  fi
}

nucleitest(){
  if [ -s $TARGETDIR/3-all-subdomain-live-scheme.txt ]; then
    echo "[$(date +%H:%M:%S)] [nuclei] technologies testing..."
    nuclei -silent -H "$CUSTOMHEADER" -rl "$REQUESTSPERSECOND" -l $TARGETDIR/3-all-subdomain-live-scheme.txt -t $HOMEDIR/nuclei-templates/technologies/ -o $TARGETDIR/nuclei/nuclei_output_technology.txt
    echo "[$(date +%H:%M:%S)] [nuclei] CVE testing..."
    nuclei -silent -iserver "https://$LISTENSERVER" \
      -H "$CUSTOMHEADER" -rl "$REQUESTSPERSECOND" \
      -o $TARGETDIR/nuclei/nuclei_output.txt \
      -l $TARGETDIR/3-all-subdomain-live-scheme.txt \
      -exclude-templates $HOMEDIR/nuclei-templates/misconfiguration/http-missing-security-headers.yaml \
      -exclude-templates $HOMEDIR/nuclei-templates/miscellaneous/old-copyright.yaml \
      -t $HOMEDIR/nuclei-templates/vulnerabilities/ \
      -t $HOMEDIR/nuclei-templates/cnvd/ \
      -t $HOMEDIR/nuclei-templates/iot/ \
      -t $HOMEDIR/nuclei-templates/cves/2013/ \
      -t $HOMEDIR/nuclei-templates/cves/2014/ \
      -t $HOMEDIR/nuclei-templates/cves/2015/ \
      -t $HOMEDIR/nuclei-templates/cves/2016/ \
      -t $HOMEDIR/nuclei-templates/cves/2017/ \
      -t $HOMEDIR/nuclei-templates/cves/2018/ \
      -t $HOMEDIR/nuclei-templates/cves/2019/ \
      -t $HOMEDIR/nuclei-templates/cves/2020/ \
      -t $HOMEDIR/nuclei-templates/cves/2021/ \
      -t $HOMEDIR/nuclei-templates/misconfiguration/ \
      -t $HOMEDIR/nuclei-templates/network/ \
      -t $HOMEDIR/nuclei-templates/miscellaneous/ \
      -t $HOMEDIR/nuclei-templates/takeovers/ \
      -t $HOMEDIR/nuclei-templates/default-logins/ \
      -t $HOMEDIR/nuclei-templates/exposures/ \
      -t $HOMEDIR/nuclei-templates/exposed-panels/ \
      -t $HOMEDIR/nuclei-templates/fuzzing/
    echo "[$(date +%H:%M:%S)] [nuclei] CVE testing done."

    if [ -s $TARGETDIR/nuclei/nuclei_output.txt ]; then
      cut -f4 -d ' ' $TARGETDIR/nuclei/nuclei_output.txt | unfurl paths | sed 's/^\///;s/\/$//;/^$/d' | sort | uniq > $TARGETDIR/nuclei/nuclei_unfurl_paths.txt
      # filter first and first-second paths from full paths and remove empty lines
      cut -f1 -d '/' $TARGETDIR/nuclei/nuclei_unfurl_paths.txt | sed '/^$/d' | sort | uniq > $TARGETDIR/nuclei/nuclei_paths.txt
      cut -f1-2 -d '/' $TARGETDIR/nuclei/nuclei_unfurl_paths.txt | sed '/^$/d' | sort | uniq >> $TARGETDIR/nuclei/nuclei_paths.txt

      # full paths+queries
      cut -f4 -d ' ' $TARGETDIR/nuclei/nuclei_output.txt | unfurl format '%p%?%q' | sed 's/^\///;s/\/$//;/^$/d' | sort | uniq > $TARGETDIR/nuclei/nuclei_paths_queries.txt
      sort -u $TARGETDIR/nuclei/nuclei_unfurl_paths.txt $TARGETDIR/nuclei/nuclei_paths.txt $TARGETDIR/nuclei/nuclei_paths_queries.txt -o $TARGETDIR/nuclei/nuclei-paths-list.txt
    fi
  fi
}

# prepare custom wordlist for
# ssrf test --fuzz only mode
# directory bruteforce using --fuzz and/or --brute mode only
custompathlist() {
  if [ -s "$TARGETDIR/3-all-subdomain-live-scheme.txt" ]; then
    # sort new assets
    sort -u "$TARGETDIR/3-all-subdomain-live-scheme.txt" -o "$TARGETDIR/3-all-subdomain-live-scheme.txt"
    # get only hostnames from full socket addresses
    < "$TARGETDIR/3-all-subdomain-live-scheme.txt" unfurl format '%d:%P' | sed "s/:$//" | tee "$TARGETDIR/3-all-subdomain-live-socket.txt" |  sed -E "s/:([[:digit:]]+)?$//" | sort -u > "$TARGETDIR/3-all-subdomain-live.txt"

    echo
    echo "[$(date +%H:%M:%S)] Prepare custom lists"
    if [[ -n "$single" || -n "$wildcard" ]]; then
      sort -u "$TARGETDIR/wayback/wayback_output.txt" "$TARGETDIR/gospider/gospider_out.txt" -o "$RAWFETCHEDLIST"
    else
      sort -u "$TARGETDIR/gospider/gospider_out.txt" -o "$RAWFETCHEDLIST"
    fi

    xargs -I '{}' echo '^https?://(w{3}\.)?([[:alnum:]_\-]+)?[.]?{}' < "$TARGETDIR/3-all-subdomain-live.txt" | grep -iEf - "$RAWFETCHEDLIST" | sed "$UNWANTEDQUERIES" > "$FILTEREDFETCHEDLIST" || true

    if [[ -n "$brute" || -n "$single" || -n "$wildcard" ]]; then
      echo "Prepare custom CUSTOMFFUFWORDLIST"
      # filter first and first-second paths from full paths
      # remove empty lines
      # remove js|json|etc entries
      < "$FILTEREDFETCHEDLIST" unfurl paths | sed 's/^\///;/^$/d;/web.archive.org/d;/@/d' \
        | cut -f1-2 -d '/' \
        | sort -u \
        | sed 's/\/$//' \
        | grep -viE -e "(([[:alnum:][:punct:]]+)+)[.](js|json)" -e "((https?://)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](${JUICYFILETYPES})" > "$CUSTOMFFUFWORDLIST" || true

      sort -u "$CUSTOMFFUFWORDLIST" -o "$CUSTOMFFUFWORDLIST"
    fi

    # js & json
    grep -ioE "(([[:alnum:][:punct:]]+)+)[.](js|json)" "$FILTEREDFETCHEDLIST" | $CHECKHTTPX2XX -nfs > "$TARGETDIR/tmp/js-list.txt" || true
    # txt, log & other stuff
    grep -ioE "((https?://)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](${JUICYFILETYPES})" "$FILTEREDFETCHEDLIST" > "$TARGETDIR/tmp/juicy-files-list.txt" || true

    # SSRF list
    sed 's|^|^https?://(([[:alnum:][:punct:]]+)+)?|; s|$|=|' < "$PARAMSLIST" | grep -oiEf - "$FILTEREDFETCHEDLIST" >> "$CUSTOMSSRFQUERYLIST" || true

    # SQLi list
    grep -oiE "(([[:alnum:][:punct:]]+)+)?(php3?|aspx)\?[[:alnum:]]+=([[:alnum:][:punct:]]+)?" "$FILTEREDFETCHEDLIST" > "$CUSTOMSQLIQUERYLIST" || true

    sort -u "$CUSTOMSSRFQUERYLIST" -o "$CUSTOMSSRFQUERYLIST"
    sort -u "$CUSTOMSQLIQUERYLIST" -o "$CUSTOMSQLIQUERYLIST"

    # LFI list
    grep -oiE "(([[:alnum:][:punct:]]+)+)?(cat|dir|doc|attach|cmd|location|file|download|path|include|include_once|require|require_once|document|root|php_path|admin|debug|log)=" "$CUSTOMSSRFQUERYLIST" \
      | qsreplace -a > "$CUSTOMLFIQUERYLIST" || true

    grep -oiE -e "(([[:alnum:][:punct:]]+)+)?=(([[:alnum:][:punct:]]+)+)\.(pdf|txt|log|md|php|json|csv|src|bak|old|jsp|sql|zip|xls|dll)" \
      -e "(([[:alnum:][:punct:]]+)+)?(php3?|aspx)\?[[:alnum:]]+=([[:alnum:][:punct:]]+)?" "$FILTEREDFETCHEDLIST" \
      | grep -oiE -e "((https?://)|www\.)(([[:alnum:][:punct:]]+)+)=" -e "((https?://)|www\.)(([[:alnum:][:punct:]]+)+)\?[[:alnum:]]+=" \
      | qsreplace -a  >> "$CUSTOMLFIQUERYLIST" || true

    sort -u "$CUSTOMLFIQUERYLIST" -o "$CUSTOMLFIQUERYLIST"

    < "$CUSTOMSSRFQUERYLIST" unfurl format '%p%?%q' | sed "/^\/\;/d;/^\/\:/d;/^\/\'/d;/^\/\,/d;/^\/\./d" | qsreplace -a > "$TARGETDIR/ssrf-path-list.txt"
    sort -u "$TARGETDIR/ssrf-path-list.txt" -o "$TARGETDIR/ssrf-path-list.txt"
    echo "[$(date +%H:%M:%S)] Custom done."
  fi
}


linkfindercrawling(){
  if [ -s $TARGETDIR/tmp/js-list.txt ]; then
    echo "[$(date +%H:%M:%S)] linkfinder crawling"
    sort -u $TARGETDIR/tmp/js-list.txt -o $TARGETDIR/tmp/js-list.txt

    mkdir -p $TARGETDIR/linkfinder/
    echo "[$(date +%H:%M:%S)] linkfinder"
    interlace --silent -tL "$TARGETDIR/tmp/js-list.txt" -threads 10 -c "linkfinder -i _target_ -o cli" | tee $TARGETDIR/linkfinder/linkfinder_out.txt
    echo "[$(date +%H:%M:%S)] linkfinder done"

    if [ -s $TARGETDIR/linkfinder/linkfinder_out.txt ]; then
      sed "${SEDOPTION[@]}" $UNWANTEDPATHS $TARGETDIR/linkfinder/linkfinder_out.txt
      sort -u $TARGETDIR/linkfinder/linkfinder_out.txt -o $TARGETDIR/linkfinder/linkfinder_out.txt
      sed "${SEDOPTION[@]}" 's/\\//g' $TARGETDIR/linkfinder/linkfinder_out.txt

      echo "[debug] linkfinder: search for js|json"
      cut -f2 -d ' ' $TARGETDIR/linkfinder/linkfinder_out.txt | grep -iE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](js|json)" > $TARGETDIR/tmp/linkfinder-js-list.txt || true
      echo "[debug] linkfinder: search for juicy files"
      cut -f2 -d ' ' $TARGETDIR/linkfinder/linkfinder_out.txt | grep -iE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](${JUICYFILETYPES})" >> $TARGETDIR/tmp/juicy-files-list.txt || true

      echo "[debug] linkfinder: concat source URL with found path from this URL"
      # [https://54.68.201.132/static/main.js] /api/widget_settings/metadata --> https://54.68.201.132/api/widget_settings/metadata
      while read line; do
        url=$(echo "$line" | sed 's/[[]//;s/[]]//' | awk '{ print $1 }' | unfurl format '%s://%d')
        path2=$(echo "$line" | awk '{ print $2 }' | grep -oE "^/{1}[[:alpha:]]+[.]?(([[:alnum:][:punct:]]+)+)" || true)
        if [[ -n "$path2" ]]; then
          echo "$url$path2" >> $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt
        fi
      done < $TARGETDIR/linkfinder/linkfinder_out.txt

      if [ -s $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt ]; then
        sed "${SEDOPTION[@]}" $UNWANTEDPATHS $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt
        sort -u $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt -o $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt
        # prepare additional js/json queries
        grep -iE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](js|json)" $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt >> $TARGETDIR/tmp/linkfinder-js-list.txt || true
        grep -iE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](${JUICYFILETYPES})" $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt >> $TARGETDIR/tmp/juicy-files-list.txt || true
      fi

      if [ -s $TARGETDIR/tmp/linkfinder-js-list.txt ]; then
        sort -u $TARGETDIR/tmp/linkfinder-js-list.txt -o $TARGETDIR/tmp/linkfinder-js-list.txt
        # filter out in scope
        xargs -I '{}' echo {} < $TARGETDIR/3-all-subdomain-live.txt | grep -iEf - $TARGETDIR/tmp/linkfinder-js-list.txt | $CHECKHTTPX2XX -nfs > $TARGETDIR/tmp/js-list-2.txt || true

        if [ -s "$TARGETDIR"/tmp/js-list-2.txt ]; then
          sort -u $TARGETDIR/tmp/js-list-2.txt -o $TARGETDIR/tmp/js-list-2.txt
          # call linkfinder with new js-list-2
          echo "[$(date +%H:%M:%S)] linkfinder-2"
          mkdir -p $TARGETDIR/linkfinder_2
          interlace --silent -tL "$TARGETDIR/tmp/js-list-2.txt" -threads 10 -c "linkfinder -i _target_ -o cli" | tee $TARGETDIR/linkfinder_2/linkfinder_out.txt

          if [ -s $TARGETDIR/linkfinder_2/linkfinder_out.txt ]; then
            sed "${SEDOPTION[@]}" $UNWANTEDPATHS $TARGETDIR/linkfinder_2/linkfinder_out.txt
            echo "[$(date +%H:%M:%S)] linkfinder-2 done"

            cut -f2 -d ' ' $TARGETDIR/linkfinder_2/linkfinder_out.txt | grep -iE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](js|json)" > $TARGETDIR/tmp/linkfinder_2_js_list.txt || true
            cut -f2 -d ' ' $TARGETDIR/linkfinder_2/linkfinder_out.txt | grep -iE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](${JUICYFILETYPES})" >> $TARGETDIR/tmp/juicy-files-list.txt || true

            while read line; do
              url=$(echo "$line" | sed 's/[[]//;s/[]]//' | awk '{ print $1 }' | unfurl format '%s://%d')
              path2=$(echo "$line" | awk '{ print $2 }' | grep -oE "^/{1}[[:alpha:]]+[.]?(([[:alnum:][:punct:]]+)+)" || true)
              if [[ -n "$path2" ]]; then
                echo "$url$path2" >> $TARGETDIR/tmp/linkfinder_2_concatenated_path_list.txt
              fi
            done < $TARGETDIR/linkfinder_2/linkfinder_out.txt

            if [ -s $TARGETDIR/tmp/linkfinder_2_concatenated_path_list.txt ]; then
              sed "${SEDOPTION[@]}" $UNWANTEDPATHS $TARGETDIR/tmp/linkfinder_2_concatenated_path_list.txt
              sort -u $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt $TARGETDIR/tmp/linkfinder_2_concatenated_path_list.txt -o $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt
              # prepare additional js/json queries
              grep -iE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](js|json)" $TARGETDIR/tmp/linkfinder_2_concatenated_path_list.txt >> $TARGETDIR/tmp/linkfinder_2_js_list.txt || true
              grep -iE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](${JUICYFILETYPES})" $TARGETDIR/tmp/linkfinder_2_concatenated_path_list.txt >> $TARGETDIR/tmp/juicy-files-list.txt || true
            fi

            if [ -s $TARGETDIR/tmp/linkfinder_2_js_list.txt ]; then
              xargs -I '{}' echo {} < $TARGETDIR/3-all-subdomain-live.txt | grep -iEf - $TARGETDIR/tmp/linkfinder_2_js_list.txt | $CHECKHTTPX2XX -nfs >> $TARGETDIR/tmp/js-list-2.txt || true
              # final js list after 2 recursion of linkfinder
              [[ -s $TARGETDIR/tmp/js-list-2.txt ]] && sort -u $TARGETDIR/tmp/js-list-2.txt $TARGETDIR/tmp/js-list.txt -o $TARGETDIR/tmp/js-list.txt
            fi
          fi
        fi
      fi
    fi

    # prepare additional path for bruteforce
    if [[ -n "$brute" && -s "${TARGETDIR}/tmp/linkfinder-concatenated-path-list.txt" ]]; then
      echo "[$(date +%H:%M:%S)] bruteforce collected paths"
      grep -viE "((https?:\/\/)|www\.)(([[:alnum:][:punct:]]+)+)?[.]?(([[:alnum:][:punct:]]+)+)[.](js|json|${JUICYFILETYPES})" $TARGETDIR/tmp/linkfinder-concatenated-path-list.txt > $TARGETDIR/tmp/linkfinder-path-list.txt || true
      [[ -s $TARGETDIR/tmp/linkfinder-path-list.txt ]] && $CHECKHTTPX2XX -nfs -content-length -l $TARGETDIR/tmp/linkfinder-path-list.txt -o $TARGETDIR/bruteforce_out.txt
      echo "[$(date +%H:%M:%S)] bruteforce done"
    fi

    # probe for 2xx juicy files
    if [[ -s $TARGETDIR/tmp/juicy-files-list.txt ]]; then
      echo "$(date +%H:%M:%S)] juicy files probe"
      $CHECKHTTPX2XX -nfs -content-length -l $TARGETDIR/tmp/juicy-files-list.txt -o $TARGETDIR/juicy_out.txt
      echo "$(date +%H:%M:%S)] juicy done"
    fi
  fi
}

secretfinder(){
  # test means if linkfinder did not provide any output secretfinder testing makes no sense
  if [ -s $TARGETDIR/tmp/js-list.txt ]; then
    echo "$(date +%H:%M:%S)] secretfinder"
    mkdir -p $TARGETDIR/secretfinder/
    interlace --silent -tL "$TARGETDIR/tmp/js-list.txt" -threads 10 -c "secretfinder -i _target_ -o cli" | tee $TARGETDIR/secretfinder/secretfinder_out.txt
    echo "$(date +%H:%M:%S)] secretfinder done"

    echo "$(date +%H:%M:%S)] getsecrets"
    getsecrets "$TARGETDIR/tmp/js-list.txt" > $TARGETDIR/getsecrets_out.txt
    echo "$(date +%H:%M:%S)] getsecrets done"
  fi
}


ssrftest(){
  if [ -s $TARGETDIR/3-all-subdomain-live-scheme.txt ]; then
    echo "[$(date +%H:%M:%S)] [SSRF-2] Blind probe..."
        ffuf -s -timeout 1 -ignore-body -u HOST/\?url=https://${LISTENSERVER}/DOMAIN/{} \
            -w $TARGETDIR/3-all-subdomain-live-scheme.txt:HOST \
            -w $TARGETDIR/3-all-subdomain-live-socket.txt:DOMAIN \
            -t 1 \
            -p 0.5 \
            -H "$CUSTOMHEADER" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0" \
            -mode pitchfork > /dev/null
    echo "[$(date +%H:%M:%S)] [SSRF-2] done."
    echo
    if [[ -s "$CUSTOMSSRFQUERYLIST" ]]; then
      echo "[$(date +%H:%M:%S)] [SSRF-3] fuzz original endpoints from wayback and fetched data"
      ENDPOINTCOUNT=$(< $CUSTOMSSRFQUERYLIST wc -l)
      echo "requests count = $ENDPOINTCOUNT"
          ffuf -s -timeout 1 -ignore-body -u HOST${LISTENSERVER} \
               -w $CUSTOMSSRFQUERYLIST:HOST \
               -t 1 \
               -p 0.5 \
               -H "$CUSTOMHEADER" \
               -H "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50" \
               > /dev/null
      echo "[$(date +%H:%M:%S)] [SSRF-3] done."
    fi
  fi
}


lfitest(){
  if [[ -s "$CUSTOMLFIQUERYLIST" ]]; then
    echo
    echo "[$(date +%H:%M:%S)] [LFI] ffuf with all live servers with lfi-path-list using wordlist/LFI-payload.txt..."
    ffuf -s -timeout 5 -u HOSTPATH \
      -w $CUSTOMLFIQUERYLIST:HOST \
      -w $LFIPAYLOAD:PATH \
      -mr "root:[x*]|admin|password|localhost|PRIVATE|ssh-rsa|mysql|BASH|credentials" \
      -H "$CUSTOMHEADER" \
      -t "$NUMBEROFTHREADS" \
      -rate "$REQUESTSPERSECOND" \
      -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36" \
      -o $TARGETDIR/ffuf/lfi-matched-url.html -of html -or true > /dev/null
    echo "[$(date +%H:%M:%S)] [LFI] done."
  fi
  if [ -s $TARGETDIR/3-all-subdomain-live-scheme.txt ]; then
    echo "[$(date +%H:%M:%S)] [LFI] nuclei fuzz for LFI"
    nuclei -silent -H "$CUSTOMHEADER" -rl "$REQUESTSPERSECOND" \
      -l $TARGETDIR/3-all-subdomain-live-scheme.txt \
      -t "${PWD}/wordlist/storenth-lfi.yaml" \
      -o $TARGETDIR/nuclei/nuclei_lfi_out.txt \
    echo "[$(date +%H:%M:%S)] [LFI] done."
  fi
}

sqlmaptest(){
  if [[ -s "$CUSTOMSQLIQUERYLIST" ]]; then
    echo "[$(date +%H:%M:%S)] [sqlmap] SQLi testing..."
    sqlmap -m $CUSTOMSQLIQUERYLIST --batch --random-agent -f --banner --ignore-code=404 --output-dir=$TARGETDIR/sqlmap/
    echo "[$(date +%H:%M:%S)] [sqlmap] done."
  fi
}

sqli_test(){

  gf sqli $CUSTOMSUBDOMAINSWORDLIST > sqli_endpoints.txt

  uro -i sqli_endpoints.txt -o sqli_endpoints_uniq.txt

  sqlmap -m sqli_endpoints_uniq.txt --batch --random-agent --level=3 --risk=3 | tee sqlmap_output.txt

}


masscantest(){
  if [ -s $TARGETDIR/dnsprobe_ip.txt ]; then
    echo "[$(date +%H:%M:%S)] [masscan] Looking for open ports..."
    
    naabu -silent -rate 900 -p 0-1000,2375,3306,3389,4990,5432,5900,6379,6066,8080,8383,8500,8880,8983,9000,27017 -l $TARGETDIR/dnsprobe_ip.txt -o $TARGETDIR/naabu_out
    echo "[$(date +%H:%M:%S)] [masscan] done."
  fi
  if [ -s $TARGETDIR/dnsprobe_subdomains.txt ]; then
    echo "[$(date +%H:%M:%S)] [naabu] Looking for open ports for domains..."
    naabu -silent -rate 900 -p 0-1000,2375,3306,3389,4990,5432,5900,6379,6066,8080,8383,8500,8880,8983,9000,27017 -l $TARGETDIR/dnsprobe_subdomains.txt >> $TARGETDIR/naabu_out
    echo "[$(date +%H:%M:%S)] [naabu] done."
  fi
}

nmap_nse(){
  echo "[$(date +%H:%M:%S)] [nmap] scanning..."
  mkdir $TARGETDIR/nmap
  while read line; do
    IP=$(echo $line | awk '{ print $4 }')
    PORT=$(echo $line | awk -F '[/ ]+' '{print $7}')
    FILENAME=$(echo $line | awk -v PORT=$PORT '{ print "nmap_"PORT"_"$4}' )

    echo "[nmap] scanning $IP using $PORT port"
    nmap --spoof-mac 0 -n -sV --version-intensity 9 --script=default,http-headers -sS -Pn -T4 -f -p$PORT -oG $TARGETDIR/nmap/$FILENAME $IP
    
  done < $TARGETDIR/masscan_output.gnmap
  echo "[$(date +%H:%M:%S)] [nmap] done."
}

# directory bruteforce
ffufbrute(){
  if [ -s "${CUSTOMFFUFWORDLIST}" ]; then
    
    echo "[$(date +%H:%M:%S)] Start directory bruteforce using ffuf..."
    ffuf -timeout 7 -u HOST/PATH -mc 200,201,202,401 -fs 0 \
      -w $TARGETDIR/3-all-subdomain-live-scheme.txt:HOST \
      -w $CUSTOMFFUFWORDLIST:PATH \
      -t 2 \
      -p 0.5 \
      -H "$CUSTOMHEADER" \
      -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Safari/537.36" \
      -o $TARGETDIR/ffuf/directory-brute.html -of html -or true
    echo "[$(date +%H:%M:%S)] directory bruteforce done."
  fi
}

apibruteforce(){
    echo
    echo "[$(date +%H:%M:%S)] Start API endpoints bruteforce using ffuf..."
    # API bruteforce
    ffuf -s -u HOSTPATH \
      -w $TARGETDIR/3-all-subdomain-live-scheme.txt:HOST \
      -w $APIWORDLIST:PATH
      -timeout 5 \
      -mc 200,201,202 \
      -t 2 \
      -p 0.5 \
      -H "$CUSTOMHEADER" \
      -o $TARGETDIR/ffuf/api-brute.html -of html -or true

    echo "[$(date +%H:%M:%S)] API bruteforce done"
}


recon(){
  enumeratesubdomains $1
  echo "enumeratesubdomains DONE"

  if [[ -n "$single" || -n "$wildcard" ]]; then
    checkwaybackurls $1
    echo "checkwaybackurls DONE"
  fi

  sortsubdomains $1
  echo "sortsubdomains DONE"
  dnsbruteforcing $1
  echo "dnsbruteforcing DONE"
  permutatesubdomains $1
  echo "permutatesubdomains DONE"

  dnsprobing $1
  echo "permutatesubdomains DONE"
  checkhttprobe $1 &
  PID_HTTPX=$!
  echo "wait PID_HTTPX=$PID_HTTPX"
  wait $PID_HTTPX
  echo "checkhttprobe DONE"

  #if [[ -n "$fuzz" || -n "$brute" || -n "$wildcard" ]]; then
    gospidertest $1
    custompathlist $1
    linkfindercrawling $1
    secretfinder $1
  #fi

  screenshots $1 &
  PID_SCREEN=$!
  echo "Waiting for screenshots ${PID_SCREEN}"
  wait $PID_SCREEN
  echo "screenshots DONE"

  # nucleitest $1 &
  # PID_NUCLEI=$!
  # echo "Waiting for nucleitest ${PID_NUCLEI}..."
  # wait $PID_NUCLEI
  # echo "nucleitest DONE"


  if [[ -n "$fuzz" || -n "$wildcard" ]]; then
    ssrftest $1
    lfitest $1
    sqlmaptest $1
    sqli_test $1
  fi

  if [[ -n "$brute" ]]; then
    ffufbrute $1 
  fi

  bypass403test $1
  masscantest $1

  echo "Recon done!"
}

report(){
  echo "Generating HTML-report here..."
  ./helpers/report.sh $1 $TARGETDIR > $TARGETDIR/report.html
  $CHROMIUM --headless --disable-gpu --no-sandbox --print-to-pdf=${TARGETDIR}/report.pdf file://${TARGETDIR}/report.html
  echo "Report done!"
}


# Program Start Here....
main(){
  # collect wildcard and single targets statistic to retest later (optional)
  if [[ -n "$wildcard" ]]; then
    if [ -s $STORAGEDIR/wildcard.txt ]; then
      if ! grep -Fxq $1 $STORAGEDIR/wildcard.txt; then
        echo $1 >> $STORAGEDIR/wildcard.txt
      fi
    fi
  fi

  if [[ -n "$single" ]]; then
    if [ -s $STORAGEDIR/single.txt ]; then
      if ! grep -Fxq $1 $STORAGEDIR/single.txt; then
        echo $1 >> $STORAGEDIR/single.txt
      fi
    fi
  fi

  # parse cidr input to create valid directory
  if [[ -n "$cidr" ]]; then
    CIDRFILEDIR=$(echo $1 | sed "s/\//_/")
    TARGETDIR=$STORAGEDIR/$CIDRFILEDIR/$foldername
    if [ -d "$STORAGEDIR/$CIDRFILEDIR" ]; then
      echo "This is a known target."
    else
      mkdir -p $STORAGEDIR/$CIDRFILEDIR
    fi
  elif [[ -n "$list" ]]; then
    LISTFILEDIR=$(basename $1 | sed 's/[.]txt$//')
    TARGETDIR=$STORAGEDIR/$LISTFILEDIR/$foldername
    if [ -d "$STORAGEDIR/$LISTFILEDIR" ]; then
      echo "This is a known target."
    else
      mkdir -p $STORAGEDIR/$LISTFILEDIR
    fi
  else
    TARGETDIR=$STORAGEDIR/$1/$foldername
    if [ -d "$STORAGEDIR/$1" ]; then
      echo "This is a known target."
    else
      mkdir -p $STORAGEDIR/$1
    fi
  fi
  mkdir -p $TARGETDIR
  [[ -d $TARGETDIR/tmp ]] || mkdir $TARGETDIR/tmp
  echo "target dir created: $TARGETDIR"

  if [[ -n "$fuzz" ]]; then
    echo "Starting up listen server..."
    # Listen server
    interactsh-client -v -json -o $TARGETDIR/_listen_server_out.log &> $TARGETDIR/_listen_server.log &
    SERVER_PID=$!
    echo $SERVER_PID
    sleep 5

    MAXCOUNT=0
    while [ $MAXCOUNT -le 10 ]; do
      X=$((X+1))
      echo $MAXCOUNT
      LISTENSERVER=$(tail -n1 $TARGETDIR/_listen_server.log)
      if [[ -n "$LISTENSERVER" ]]; then
          LISTENSERVER=$(echo $LISTENSERVER | cut -f2 -d ' ')
          break
      fi
      sleep 5
    done

    if echo "$LISTENSERVER" | grep -e "oast"; then
      echo "Listen server is up $LISTENSERVER with PID=$SERVER_PID"
      echo $LISTENSERVER > $TARGETDIR/_listen_server_file
    else
    # try to use alternative interactsh-client -v -json -server https://interact.sh
      echo "Listen server failed to start"
      exit 1
    fi
    echo
  fi

  # collect call parameters
  echo "$@" >> $TARGETDIR/_call_params.txt
  echo "$@" >> ./_call.log


  # merged and filtered from unwanted paths from gospider and page-fetch list
  FILTEREDFETCHEDLIST=$TARGETDIR/tmp/filtered_fetched_list.txt
  touch $FILTEREDFETCHEDLIST
  # scope filtered list
  RAWFETCHEDLIST=$TARGETDIR/tmp/raw_fetched_list.txt
  touch $RAWFETCHEDLIST

  if [[ -n "$fuzz" || -n "$brute" ]]; then
    mkdir $TARGETDIR/ffuf/
    mkdir $TARGETDIR/gospider/
    # mkdir $TARGETDIR/page-fetched/
    # touch $TARGETDIR/page-fetched/pagefetcher_output.txt
  fi

  # # used for fuzz and bruteforce
  if [[ -n "$fuzz" ]]; then
    # to work with gf ssrf output
    CUSTOMSSRFQUERYLIST=$TARGETDIR/tmp/custom_ssrf_list.txt
    touch $CUSTOMSSRFQUERYLIST
    # to work with gf lfi output
    CUSTOMLFIQUERYLIST=$TARGETDIR/tmp/custom_lfi_list.txt
    touch $CUSTOMLFIQUERYLIST
    # to work with gf ssrf output
    CUSTOMSQLIQUERYLIST=$TARGETDIR/tmp/custom_sqli_list.txt
    touch $CUSTOMSQLIQUERYLIST
  fi

  # # ffuf dir uses to store brute output
  if [[ -n "$brute" ]]; then
    CUSTOMFFUFWORDLIST=$TARGETDIR/tmp/custom_ffuf_wordlist.txt
    touch $CUSTOMFFUFWORDLIST
  fi

  # used to save target specific list for alterations (shuffledns, altdns)
  if [ "$alt" = "1" ]; then
    CUSTOMSUBDOMAINSWORDLIST=$TARGETDIR/tmp/custom_subdomains_wordlist.txt
    touch $CUSTOMSUBDOMAINSWORDLIST
    cp $ALTDNSWORDLIST $CUSTOMSUBDOMAINSWORDLIST
  fi

  # nuclei output
  mkdir $TARGETDIR/nuclei/

  if [ "$mad" = "1" ]; then
    # gau/waybackurls output
    mkdir $TARGETDIR/wayback/
  fi
  # subfinder list of subdomains
  touch $TARGETDIR/subfinder-list.txt 
  # assetfinder list of subdomains
  touch $TARGETDIR/assetfinder-list.txt
  # all assetfinder/subfinder finded domains
  touch $TARGETDIR/enumerated-subdomains.txt
  # gau/waybackurls list of subdomains
  touch $TARGETDIR/wayback-subdomains-list.txt

  # clean up when script receives a signal
  trap clean_up SIGINT

    recon $1
    report $1
}

clean_up() {
  # Perform program interupt housekeeping
  echo
  echo "SIGINT received"
  echo "clean_up..."
  echo "housekeeping rm -rf $TARGETDIR"
  rm -rf $TARGETDIR
  kill_listen_server
  kill_background_pid
  exit 0
}

usage(){
  PROGNAME=$(basename $0)
  echo "Usage: sudo ./zirecon.sh <target> [[-b] | [--brute]] [[-w] | [--wildcard]]"
  echo "Example: sudo $PROGNAME example.com --wildcard"
}

invokation(){
  echo "Warn: unexpected positional argument: $1"
  echo "$(basename $0) [[-h] | [--help]]"
}

# check for help arguments or exit with no arguments
checkhelp(){
  while [ "$1" != "" ]; do
      case $1 in
          -h | --help )           usage
                                  exit
                                  ;;
      esac
      shift
  done
}

# check for specifiec arguments (help)
checkargs(){
  while [ "$1" != "" ]; do
      case $1 in
          -s | --single )         single="1"          
                                  ;;
          -f | --fuzz )           fuzz="1"
                                  ;;
          -w | --wildcard )       wildcard="1"
                                  ;;
          -b | --brute )          brute="1"
                                  ;;
          -q | --quiet )          quiet="1"
                                  ;;
      esac
      shift
  done
}

if [ $# -eq 0 ]; then
    echo "Error: expected positional arguments"
    usage
    exit 1
else
  if [ $# -eq 1 ]; then
    checkhelp "$@"
  fi
fi

if [ $# -gt 1 ]; then
  checkargs "$@"
fi

if [ "$quiet" == "" ]; then
  ./helpers/logo.sh
  # env test
  echo "Check HOMEUSER: $HOMEUSER"
  echo "Check HOMEDIR: $HOMEDIR"
  echo "Check STORAGEDIR: $STORAGEDIR"
  echo
  # positional parameters test
  echo "Check params: $*"
  echo "Check # of params: $#"
  echo "Check params \$1: $1"
  echo "Check params \$single: $single"
  echo "Check params \$brute: $brute"
  echo "Check params \$fuzz: $fuzz"
  echo "Check params \$wildcard: $wildcard"
  echo
fi


# to avoid cleanup or `sort -u` operation
foldername=recon-$(date +"%y-%m-%d_%H-%M-%S")

# kill listen server
kill_listen_server(){
  if [[ -n "$SERVER_PID" ]]; then
    echo "killing listen server $SERVER_PID..."
    kill -9 $SERVER_PID &> /dev/null || true
  fi
}

# kill background and subshell
kill_background_pid(){
  echo
  echo "killing background jobs by PIDs..."
  echo "subshell before:"
  jobs -l
  jobs -l | awk '{print $2}'| xargs kill -9
  echo

  if [[ -n "$PID_SUBFINDER_FIRST" ]]; then
    echo "kill PID_SUBFINDER_FIRST $PID_SUBFINDER_FIRST"
    kill -- -${PID_SUBFINDER_FIRST} &> /dev/null || true
  fi

  if [[ -n "$PID_ASSETFINDER" ]]; then
    echo "kill PID_ASSETFINDER $PID_ASSETFINDER"
    kill -- -${PID_ASSETFINDER} &> /dev/null || true
  fi

  if [[ -n "$PID_GAU" ]]; then
    echo "kill PID_GAU $PID_GAU"
    kill -- -${PID_GAU} &> /dev/null || true
  fi

  if [[ -n "$PID_WAYBACK" ]]; then
    echo "kill PID_WAYBACK $PID_WAYBACK"
    kill -- -${PID_WAYBACK} &> /dev/null || true
  fi

  if [[ -n "$PID_HTTPX" ]]; then
    echo "kill PID_HTTPX $PID_HTTPX"
    kill -- -${PID_HTTPX} &> /dev/null || true
  fi

  if [[ -n "$PID_SCREEN" ]]; then
    echo "kill PID_SCREEN $PID_SCREEN"
    kill -- -${PID_SCREEN} &> /dev/null || true
  fi

  if [[ -n "$PID_NUCLEI" ]]; then
    echo "kill PID_NUCLEI $PID_NUCLEI"
    kill -- -${PID_NUCLEI} &> /dev/null || true
  fi

  sleep 3
  echo "subshell after:"
  jobs -l
  echo "subshell successfully done."
}

# handle script issues
error_handler(){
  echo
  echo "[ERROR]: LINENO=${LINENO}, SOURCE=$(caller)"
  echo "[ERROR]: $(basename $0): ${FUNCNAME} ${LINENO} ${BASH_LINENO[@]}"

  if [[ -s ${PWD}/_err.log ]]; then
    < ${PWD}/_err.log
  fi

  kill_listen_server
  kill_background_pid

  if [[ -n "$discord" ]]; then
    ./helpers/discord-hook.sh "[error] line $(caller): ${stats}: "
    if [[ -s ./_err.log ]]; then
      ./helpers/discord-file-hook.sh "_err.log"
    fi
  fi
  exit 1 # exit 1 force kill all subshells because of EXIT signal
}

# handle teardown
error_exit(){
  echo
  echo "[EXIT]: teardown successfully triggered"
  echo "[EXIT]: LINENO=${LINENO}, SOURCE=$(caller)"
  echo "[EXIT]: $(basename $0): ${FUNCNAME} ${LINENO} ${BASH_LINENO[@]}"
  PID_EXIT=$$
  echo "exit PID = $PID_EXIT"
  echo "jobs:"
  jobs -l
  jobs -l | awk '{print $2}' | xargs kill -9 &>/dev/null || true
  kill -- -${PID_EXIT} &>/dev/null || true
  echo "[EXIT] done."
}

# Program Invoke HERE......
main "$@"

echo "check for background and subshell"
jobs -l

kill_listen_server
exit 0