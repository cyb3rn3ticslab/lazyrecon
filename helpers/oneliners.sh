# remove empty lines/spaces
sudo sed -i '' '/^[[:space:]]*$/d' ./lazyWordLists/curated_top100.txt
cat $targetDir/wayback/wayback_output.txt | unfurl paths | sed 's/\///;/^$/d'

# remove leading / from every lines in place (rewrite the file)
sudo sed -i '' 's/\///' ./lazyWordLists/curated_top100.txt
# remove 1,2 and last lines from masscan out file
sed -i '' '1d;2d;$d' ./$1/$foldername/masscan_output.gnmap

# msfvenom shellcode payloads
/opt/metasploit-framework/bin/msfvenom -l payloads | grep ''