#!/bin/bash

while getopts ":d:" input;do
        case "$input" in
                d) domain=${OPTARG}
                        ;;
                esac
        done
if [ -z "$domain" ]     
        then
                echo "Please give a domain like \"-d domain.com\""
                exit 1
fi

# sublist3r -d $domain -v -o op.txt
subfinder -d $domain -o op.txt
assetfinder --subs-only $domain | tee -a op.txt
amass enum -passive -d $domain | tee -a op.txt
amass enum -active -d $domain -ip | tee -a amass_ips.txt
cat amass_ips.txt | awk '{print $1}' | tee -a op.txt
cat op.txt | sort -u | tee -a domains.txt

echo "Checking for alive subdomains"
cat domains.txt | httprobe | tee -a alive2.txt
cat alive2.txt | sort -u | tee -a alive_domains.txt

echo "Checking for IPs"
massdns -r /usr/share/seclists/Miscellaneous/dns-resolvers.txt -t A -o S -w massdns.raw domains.txt
cat massdns.raw | grep -e ' A ' |  cut -d 'A' -f 2 | tr -d ' ' > massdns.txt
cat massdns.txt | sort -V | uniq > IPs.txt

echo "Starting CMS detection"
whatweb -i alive_domains.txt -v --colour never | tee -a whatweb_detection.txt

echo "Starting FUZZing"
for i in $(cat alive_domains.txt);do ffuf -u $i/FUZZ -w /home/kali/.local/dirsearch/db/dicc.txt -mc 200 -t 60 -od fuzz_results; done

echo "Removing temporary files"
rm massdns.raw
rm massdns.txt
rm alive2.txt
rm op.txt
rm amass_ips.txt

echo "Recon done succesfully"
