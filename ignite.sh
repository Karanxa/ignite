#!/bin/bash

bbht(){
    mkdir /Users/karan/bbht/programs/$1/
    mkdir /Users/karan/bbht/programs/$1/domains/
    mkdir /Users/karan/bbht/programs/$1/domains/information-disclosure
    mkdir /Users/karan/bbht/programs/$1/nuclei-results/
    mkdir /Users/karan/bbht/programs/$1/subdomains/
    mkdir /Users/karan/bbht/programs/$1/wayback/
    mkdir /Users/karan/bbht/programs/$1/screenshots/
    mkdir /Users/karan/bbht/programs/$1/github/
    mkdir /Users/karan/bbht/programs/$1/wordlists/
    mkdir /Users/karan/bbht/programs/$1/endpoints/
    mkdir /Users/karan/bbht/programs/$1/poc/
    mkdir /Users/karan/bbht/programs/$1/notes/
    mkdir /Users/karan/bbht/programs/$1/imp/
    python3 /Users/karan/ignite/add_root.py $1
    cd  /Users/karan/bbht/programs/$1/
    git init  
}

add_root(){
    python3 /Users/karan/ignite/add_root.py $1
}

sub(){
    amass enum --passive -df /Users/karan/bbht/programs/$1/domains/roots.txt  -o /Users/karan/bbht/programs/$1/subdomains/domains_$1
    cat /Users/karan/bbht/programs/$1/domains/roots.txt | assetfinder --subs-only | tee -a /Users/karan/bbht/programs/$1/subdomains/domains_$1

    subfinder -dL /Users/karan/bbht/programs/$1/domains/roots.txt  -o /Users/karan/bbht/programs/$1/subdomains/domains_subfinder_$1
    cat domains_subfinder_$1 | tee -a /Users/karan/bbht/programs/$1/subdomains/domains_$1

    sort -u /Users/karan/bbht/programs/$1/subdomains/domains_$1 -o /Users/karan/bbht/programs/$1/subdomains/domains_$1
    cat /Users/karan/bbht/programs/$1/subdomains/domains_$1 | filter-resolved | tee -a /Users/karan/bbht/programs/$1/subdomains/allsubs.txt
}

subcheck(){
    subjack -w /Users/karan/bbht/subdomains/$1.txt -t 100 -o /Users/karan/bbht/results/subtoc/$1_TOC.txt -ssl -c /Users/karan/go/src/github.com/haccer/subjack/fingerprints.json -v
}

endpoints(){
    cat /Users/karan/bbht/programs/$1/domains/roots.txt | waybackurls | tee -a /Users/karan/bbht/programs/$1/endpoints/all_endpoints.txt
    cat /Users/karan/bbht/programs/$1/subdomains/allsubs.txt | waybackurls | tee -a /Users/karan/bbht/programs/$1/endpoints/all_endpoints.txt

    sort -u /Users/karan/bbht/programs/$1/endpoints/all_endpoints.txt -o /Users/karan/bbht/programs/$1/endpoints/all_endpoints.txt
    cat /Users/karan/bbht/programs/$1/endpoints/all_endpoints.txt | filter-resolved | tee -a /Users/karan/bbht/programs/$1/endpoints/allendpoints.txt
}

screenshots()
{
    cat /Users/karan/bbht/programs/$1/domains/roots.txt  | aquatone -out /Users/karan/bbht/programs/$1/screenshots/
    cat /Users/karan/bbht/programs/$1/subdomains/allsubs.txt  | aquatone -out /Users/karan/bbht/programs/$1/screenshots/
}
wordlist(){
    gau $1 | unfurl -u keys | tee -a  /Users/karan/bbht/programs/$2/wordlists/wordlist_$1.txt ; gau $1 | unfurl -u paths|tee -a  /Users/karan/bbht/programs/$2/wordlists/ends_$1.txt; sed 's#/#\n#g'  /Users/karan/bbht/programs/$2/wordlists/ends_$1.txt  | sort -u | tee -a  /Users/karan/bbht/programs/$2/wordlists/wordlist_$1.txt | sort -u ;rm  /Users/karan/bbht/programs/$2/wordlists/ends_$1.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g'  /Users/karan/bbht/programs/$2/wordlists/wordlist_$1.txt
}

find-param(){
    arjun -i /Users/karan/bbht/programs/$1/endpoints/allendpoints.txt -oJ /Users/karan/bbht/programs/$1/endpoints/params.txt
}

corscanner(){
    python /Users/karan/bbht/tools/CORScanner/cors_scan.py -i /Users/karan/bbht/subdomains/$1.txt -t 200 -o /Users/karan/bbht/results/corscan/$1_COR.txt
}

google-dorking(){
    python3 /Users/karan/bbht/tools/pagodo/pagodo.py -d $1.com -g /Users/karan/bbht/wordlists/Dorks/google.txt -l 50 -s -e 35.0 -j 1.1
}

js-files(){
   python /Users/karan/bbht/tools/LinkFinder/linkfinder.py -i /Users/karan/bbht/programs/$1/domains/roots.txt -d | tee -a /Users/karan/bbht/programs/$1/jsfiles/jsfiles_$1.txt
   python /Users/karan/bbht/tools/LinkFinder/linkfinder.py -i /Users/karan/bbht/programs/$1/domains/allsubs.txt -d | tee -a  /Users/karan/bbht/programs/$1/jsfiles/jsfiles__subs_$1.txt
}

mscan(){ #runs masscan
    sudo masscan -p 4443,2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,744 $1
}

cves(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/cves/ 
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/cves/ 
}

default-logins(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/default-logins/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/default-logins/
}

dns(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/dns/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/dns/
}

exposed-panels(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/exposed-panels/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/exposed-panels/
}

exposures(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/exposures/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/exposures/
}

file(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/file/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/file/
}

fuzzing(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/fuzzing/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/fuzzing/
}

headless(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/headless/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/headless/
}

helpers(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/helpers/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/helpers/
}

iot(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/iot/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/iot/
}

miscellaneous(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/miscellaneous/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/miscellaneous/
}

misconfiguration(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/misconfiguration/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/misconfiguration/
}

network(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/network/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/network/
}

ssl(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/ssl/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/ssl/
}

takeover(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/takeover/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/takeover/
}

technologies(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/technologies/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/technologies/
}

token-spray(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/token-spray/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/token-spray/
}

vulnerabilities(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/vulnerabilities/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/vulnerabilities/
}

vulnerabilities(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/workflows/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/workflows/
}

cnvd(){
    nuclei -l "/Users/karan/bbht/programs/$1/domains/roots.txt" -t /Users/karan/bbht/tools/nuclei-templates/cnvd/
    nuclei -l "/Users/karan/bbht/programs/$1/subdomains/allsubs.txt" -t /Users/karan/bbht/tools/nuclei-templates/cnvd/
}


nuclei-all(){
    python3 /Users/karan/ignite/https.py $1
    cves $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_cves.txt"
    default-logins $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_default-logins.txt"
    dns $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_dns.txt"
    exposed-panels $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_exposed-panels.txt"
    exposures $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_exposures.txt"
    file $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_file.txt"
    fuzzing $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_fuzzing.txt"
    headless $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_headless.txt"
    helpers $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_helpers.txt"
    iot $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_iot.txt"
    miscellaneous $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_miscellaneous.txt"
    misconfiguration $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_misconfiguration.txt"
    network $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_network.txt"
    ssl $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_ssl.txt"
    takeover $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_takeover.txt"
    technologies $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_technologies.txt"
    token-spray $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_token-spray.txt"
    vulnerabilities $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_vulnerabilities.txt"
    workflows $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_workflows.txt"
    cnvd $1 | tee -a "/Users/karan/bbht/programs/$1/nuclei-results/all_cnvd.txt"
}

ignite(){
    bbht $1
    sub $1
    endpoints $1
    #screenshots $1
    #arjun $1
    #wordlist $1
    #sub-check $1
    #google-dorking $1
    #xss $1
    #openredirect $1
    nuclei-all $1
    js-files $1
}

ignite $1

