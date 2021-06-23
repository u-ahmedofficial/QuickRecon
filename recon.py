#######################################################################
######################Important Libraries#############################
#####################################################################
import os
from os import system
import sys
from sys import argv
import argparse
import datetime
import time


#######################################################################
######################Global Variables#############################
#####################################################################
domain="";
program="";
path="";
dirsearchthreads=50;
threadings=10;
chromiumpath="/snap/bin/chromium";
auquatonethreads=5;

#######################################################################
######################Banner For logo#############################
#####################################################################
def banner():
	system("figlet Quick Recon");
	system("echo '\t\t\t	~ Coded by Umair Ahmed(E@gle Invectus)\n'");
	system("echo '#############################################################################\n\n'");


#######################################################################
#####################Actual Method for Recon Started#################
#####################################################################

def _init_():
	system("cd {}".format(path));
	system("echo 'RECON STARTED : {} \n'".format(datetime.datetime.now().time()));
	system("echo '\n'");
	system("mkdir {}/jsfiles".format(path));
	system("mkdir {}/OSINT".format(path));
	system("mkdir {}/DOMAINSFINAL/".format(path));
	system("mkdir {}/DOMAINSFINAL/SS".format(path));
	system("mkdir {}/waybackdata".format(path));
	system("mkdir {}/DOMAINSFINAL/meg".format(path));
	system("mkdir {}/DOMAINSFINAL/TAKEOVER".format(path));
	system("mkdir {}/DOMAINSFINAL/aqua".format(path));
	system("mkdir {}/DOMAINSFINAL/NMAP".format(path));
	system("mkdir {}/Output".format(path));
	system("mkdir {}/Report".format(path));


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


def Subdomains_discovery():
	system("cd {}".format(path));	#Amass

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING AMASS SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("amass enum -passive -config /Scripts/configs/config.ini -d {} -o {}/DOMAINSFINAL/amass.txt > /dev/null 2>&1".format(domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL AMASS SUBDOMAINS: {}/DOMAINSFINAL/amass.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/amass.txt| wc -l ".format(path));

	#crtsh
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING CRTSH SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("python3 /Scripts/massdns/scripts/ct.py {} > {}/DOMAINSFINAL/crtsh.txt 2> /dev/null".format(domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL CRTSH SUBDOMAINS: {}/DOMAINSFINAL/crtsh.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/crtsh.txt| wc -l ".format(path));

	#certspot
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING CERTSPOTTER SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("curl --connect-timeout 8 --max-time 15 --retry 3 --retry-delay 0 -s https://certspotter.com/api/v0/certs?domain={} | jq '.[].dns_names[]'|sed 's/\"//g'|sed 's/\*\.//g'|sort -u|uniq|grep {} > {}/DOMAINSFINAL/certspotter.txt 2> /dev/null".format(domain,domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL CERTSPOTTER SUBDOMAINS: {}/DOMAINSFINAL/certspotter.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/certspotter.txt| wc -l ".format(path));

	#waybacksubs
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING WAYBACKMACHINE SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("waybackurls {} | sed -e 's_https*://__' -e 's/\/.*//' -e 's/:.*//' -e 's/^www\.//g'|sort -u > {}/DOMAINSFINAL/waybackdoms.txt 2> /dev/null".format(domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL WAYBACKMACHINE SUBDOMAINS: {}/DOMAINSFINAL/waybackdoms.txt  \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/waybackdoms.txt| wc -l ".format(path));
	#sslcert subs

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING SSLCERT SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("true | openssl s_client -connect {}:443 2> /dev/null | openssl x509 -noout -text 2> /dev/null | grep DNS: | sed 's/ DNS://g' | sed 's/ //g' | sed 's/,/\\n/g'|sed 's/www\.//g'|sort -u > {}/DOMAINSFINAL/sslcert.txt 2> /dev/null".format(domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL SSLCERT SUBDOMAINS: {}/DOMAINSFINAL/sslcert.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/sslcert.txt| wc -l ".format(path));

	#sonarproject

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING PROJECT SONAR SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system(" curl -fsSL 'https://dns.bufferover.run/dns?q=.{}' | sed 's/\"//g' | cut -f2 -d ',' |sort -u | grep {} > {}/DOMAINSFINAL/sonar.txt 2> /dev/null ".format(domain,domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL SONAR PROJECT SUBDOMAINS: {}/DOMAINSFINAL/sonar.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/sonar.txt| wc -l ".format(path));

	#subfinder
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING SUBFINDER SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("subfinder -d {} -o {}/DOMAINSFINAL/subfinder.txt > /dev/null 2>&1".format(domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL SUBFINDER SUBDOMAINS: cat {}/DOMAINSFINAL/subfinder.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/subfinder.txt| wc -l ".format(path));

	#massdns
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING MASSDNS COMMONSPEAK SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("python3 /Scripts/massdns/scripts/subbrute.py /Scripts/commonspeak2-wordlists/subdomains/subdomains.txt {} | massdns -r /Scripts/massdns/lists/resolvers.txt -t A -q -o S | grep -v 142.54.173.92 > {}/DOMAINSFINAL/massdnscommon.txt > /dev/null 2>&1".format(domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL MASSDNS SUBDOMAINS: {}/DOMAINSFINAL/massdnscommon.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/massdnscommon.txt| wc -l ".format(path));
	system("cat {}/DOMAINSFINAL/massdnscommon.txt | awk '{print $3}' | sort -u | while read line;do wildcard=$(cat {}/DOMAINSFINAL/massdnscommon.txt | grep -m 1 \"$line\");echo \"$wildcard\" >> {}/DOMAINSFINAL/massdnscommontemp.txt;done 2> /dev/null".format(path,path,path));
	system("cat {}/DOMAINSFINAL/massdnscommontemp.txt | awk  '{print $1}' | while read line;do x=\"$line\"; echo \"${x%?}\" >> {}/DOMAINSFINAL/massdnscommonfinal.txt;done 2> /dev/null".format(path,path));

	#massdns
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING MASSDNS SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("python3 /Scripts/massdns/scripts/subbrute.py /Scripts/massdns/lists/clean-jhaddix-dns1.txt {} | massdns -r /Scripts/massdns/lists/resolvers.txt -t A -q -o S | grep -v 142.54.173.92 > {}/DOMAINSFINAL/massdns.txt > /dev/null 2>&1".format(domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL MASSDNS SUBDOMAINS: {}/DOMAINSFINAL/massdns.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/massdns.txt| wc -l ".format(path));
	system("cat {}/DOMAINSFINAL/massdns.txt | awk '{print $3}' | sort -u | while read line;do wildcard=$(cat {}/DOMAINSFINAL/massdns.txt | grep -m 1 \"$line\");echo \"$wildcard\" >> {}/DOMAINSFINAL/massdnstemp.txt;done 2> /dev/null".format(path,path,path));
	system("cat {}/DOMAINSFINAL/massdnstemp.txt | awk  '{print $1}' | while read line;do x=\"$line\"; echo \"${x%?}\" >> {}/DOMAINSFINAL/massdnsfinal.txt;done 2> /dev/null".format(path,path));

###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################

def Osint():
	system("cd {}".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  GATHERING WHOISE INFO \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\n'");
	system("whois {} | tee {}/OSINT/whois-{}.txt 2> /dev/null".format(domain,path,domain));
	system("echo '\n'");
	system("echo '\033[91m   WHOIS Saved to {}/OSINT/whois-{}.txt  \e[0m'".format(path,domain));
	#---------------------------------------------------------------#
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  GATHERING DIG INFO \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\n'");
	system("dig {} | tee {}/OSINT/dig-{}.txt 2> /dev/null".format(domain,path,domain));
	system("echo '\n'");
	system("echo '\033[91m   DIG Saved to {}/OSINT/dig-{}.txt  \e[0m'".format(path,domain));
	#---------------------------------------------------------------#
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  GATHERING HARVESTER INFO \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\n'");
	system("theHarvester -d {} -l 30 -b all | tee {}/OSINT/harvester-{}.txt 2> /dev/null".format(domain,path,domain));
	system("echo '\n'");
	system("echo '\033[91m   HARVESTER Saved to {}/OSINT/harvester-{}.txt  \e[0m'".format(path,domain));
	#---------------------------------------------------------------#
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  GATHERING WAFF INFO \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\n'");
	system("wafw00f {} |tee {}/OSINT/waffw00f-{}.txt".format(domain,path,domain));
	system("echo '\n'");
	system("echo '\033[91m   WAFF Saved to {}/OSINT/waffw00f-{}.txt  \e[0m'".format(path,domain));
	#---------------------------------------------------------------#
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  GATHERING WIG INFO \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\n'");
	system("python3 /Scripts/wig/wig.py -d -q -t 200 http://{} |tee {}/OSINT/wig-{}.txt".format(domain,path,domain));
	system("echo '\n'");
	system("echo '\033[91m   WIG Saved to {}/OSINT/wig-{}.txt  \e[0m'".format(path,domain));
	#---------------------------------------------------------------#
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  GATHERING HEADERS INFO \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\n'");
	system("curl --connect-timeout 3 -I -s -R -H 'Origin: evil.com' {} |tee {}/OSINT/headers-{}.txt  2> /dev/null".format(domain,path,domain));
	system("echo '\n'");
	system("echo '\033[91m   HEADERS Saved to {}/OSINT/headers-{}.txt  \e[0m'".format(path,domain));
	#---------------------------------------------------------------#
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  STARTING  MASSSCAN \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\n'");
	#system("nmap -sV -T3 -Pn -p80,81,113,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017,20,21,22,23,25,53,69,389,5900,5901,5902,3306,1433,1434,1234,4000,2076,2075,6443,3868,3366,5432,15672,9999,161,4044,7077,4040,8089,7447,7080,5673,7443,19000,19080 {} -oN {}/OSINT/nmap-report-{}.txt -v 2> /dev/null".format(domain,path,domain));
	system("masscan -p1-65535 $(dig +short {}) -oL {}/OSINT/nmap-report-{}.txt --rate 10000 2> /dev/null".format(domain,path,domain));
	system("echo '\033[91m   MASSSCAN Saved to {}/OSINT/nmap-report-{}.txt  \e[0m'".format(path,domain));

###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################

def Subdomain_sort():
	# Arranging subdomains gathered from all the ScriptsHUnt #
	system("cd {}".format(path));
	system("echo '\n'");
	system("cat {}/DOMAINSFINAL/amass.txt|sort -u > {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/subfinder.txt|sort -u >> {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/crtsh.txt|sort -u >> {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/certspotter.txt|sort -u >> {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/waybackdoms.txt|sort -u >> {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/sslcert.txt|sort -u >> {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/massdnsfinal.txt|sort -u >> {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/massdnscommonfinal.txt|sort -u >> {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/sonar.txt|sort -u >> {}/DOMAINSFINAL/all.txt 2> /dev/null".format(path,path));

	system("cat {}/DOMAINSFINAL/all.txt|sort -u| sed 's/^www\.//g'|sed 's/^*\.//g'|sed 's/^-\.//g'|sed 's/^\.//g'|sed 's/^http\:\/\///g'|sed 's/^https\:\/\///g'|sed '/^$/d'|sed '/^wwww/d' |sed '/^\([0-9]\{0,3\}\.\)\{3\}[0-9]\{0,3\}/d'| grep {} |sort -u >  {}/DOMAINSFINAL/allsorted.txt 2> /dev/null".format(path,domain,path));
	
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERED SUBDOMAINS  RESOLVING \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/allsorted.txt |httprobe -c 70 |sed 's/http\:\/\///g'|sed 's/https\:\/\///g'|sed 's/\/$//g'|sort -u| tee {}/DOMAINSFINAL/domainsall.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL RESOLVED SUBDOMAINS: {}/DOMAINSFINAL/domainsall.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/domainsall.txt| wc -l ".format(path));


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


# Dig to all the subdomains #
def Takeover():
	system("cd {}".format(path));
	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING SUBDOMAINS  TAKEOVER \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/domainsall.txt| xargs -P {} -I{{}} sh -c 'dig CNAME {{}} >> {}/DOMAINSFINAL/TAKEOVER/digcom.txt && echo \'--------------------------------\' >> {}/DOMAINSFINAL/TAKEOVER/digcom.txt' 2> /dev/null".format(path,threadings,path,path));
	system("cat {}/DOMAINSFINAL/TAKEOVER/digcom.txt|egrep -i \"surge|tilda|zendesk|pantheon|intercom|mashery|acquia|smartling|Help Scout|JetBrains|Azure|Surge.sh|akamai|wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp\" | tee {}/DOMAINSFINAL/TAKEOVER/takeover.txt 2> /dev/null".format(path,domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL SUBDOMAINS TAKEOVER: {}/DOMAINSFINAL/TAKEOVER/takeover.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/TAKEOVER/takeover.txt| wc -l ".format(path));

	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING NS SUBDOMAINS  TAKEOVER \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/domainsall.txt| xargs -P {} -I{{}} sh -c 'host {{}} >> {}/DOMAINSFINAL/TAKEOVER/hostcom.txt && echo \"--------------------------------\" >> {}/DOMAINSFINAL/TAKEOVER/hostcom.txt' 2> /dev/null".format(path,threadings,path,path));
	system("cat {}/DOMAINSFINAL/TAKEOVER/hostcom.txt|egrep -i \"NXDOMAIN\" | tee {}/DOMAINSFINAL/TAKEOVER/takeoverns.txt 2> /dev/null ".format(path,domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  TOTAL SUBDOMAINS TAKEOVER: {}/DOMAINSFINAL/TAKEOVER/takeoverns.txt \e[0m'".format(path));
	system("cat {}/DOMAINSFINAL/takeoverns.txt| wc -l ".format(path));
'''

	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING SUBDOMAINS  HEADERS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/domainsall.txt| xargs -P {} -I{{}} sh -c 'curl --connect-timeout 3 -I -s -R -H \" Origin: evil.com \" {{}} > {}/DOMAINSFINAL/Headers/{{}}' 2> /dev/null".format(path,threadings,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  HEADERS SAVED TO: {}/DOMAINSFINAL/Headers  \e[0m'".format(path));
'''




###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


def Cleamtemp():
	system("rm {}/DOMAINSFINAL/massdnstemp.txt".format(path));
	system("rm {}/DOMAINSFINAL/massdnscommontemp.txt".format(path));
	system("rm {}/DOMAINSFINAL/all.txt".format(path));



###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################

def Aquatone():
	
	system("cd {}".format(path));
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  PROBING FOR DOMAINS PROTOCOLS (HTTPROBE) \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/domainsall.txt|httprobe -c 50 |sort -u > {}/DOMAINSFINAL/headerdoms.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  PROBING ENDED, TOTAL DOMAINS:    \e[0m'");
	system("cat {}/DOMAINSFINAL/headerdoms.txt |wc -l".format(path));

	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  STARTING AQUATONE DISCOVER \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/headerdoms.txt | aquatone -chrome-path {} -out {}/DOMAINSFINAL/aqua -threads {} -silent > /dev/null 2>&1".format(path,chromiumpath,path,auquatonethreads));
	system("cd {}/DOMAINSFINAL/aqua".format(path));
	system("gf urls|sort -u|uniq | grep -a {} >> {}/waybackdata/sourceurls.txt".format(domain,path));
	system("cat {}/waybackdata/sourceurls.txt | sort -u| uniq | unfurl --unique paths >> {}/waybackdata/pathlist.txt".format(path,path));
	system("cat {}/waybackdata/sourceurls.txt | sort -u| uniq | unfurl --unique keys >> {}/waybackdata/paramlist.txt".format(path,path));
	system("cat {}/waybackdata/sourceurls.txt | sort -u| uniq | unfurl --unique domains >> {}/waybackdata/domains.txt".format(path,path));
	system("cd {}".format(path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  AQUATONE DISCOVER COMPLETED \e[0m'");


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


def Screenshots():
	system("cd {}".format(path));
	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING SUBDOMAINS  SCREENSHOTS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("python /Scripts/webscreenshot/webscreenshot.py -i {}/DOMAINSFINAL/domainsall.txt -m -o {}/DOMAINSFINAL/SS/ -t 5 > /dev/null 2>&1".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  SCREENSHOTS DONE AT: {}/DOMAINSFINAL/SS/ \e[0m'".format(path));




###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################

def CloudS3():
	system("cd {}".format(path));
	# Cloud Scrapper #
	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING CLOUDSCRAPPER  S3 BUCKETS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("python /Scripts/CloudScraper/CloudScraper.py -l {}/DOMAINSFINAL/domainsall.txt |tee {}/OSINT/cloudscrapperS3.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  CLOUDSCRAPPER S3 BUCKETS DONE AT: {}/OSINT/cloudscrapperS3.txt  \e[0m'".format(path));

	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING SLURP  S3 BUCKETS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("/Scripts/slurp/slurp-linux-amd64 domain -p /Scripts/slurp/permutations.json -t {} |tee {}/OSINT/slurpS3.txt 2> /dev/null".format(domain,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  SLURP S3 BUCKETS DONE AT: {}/OSINT/slurpS3.txt  \e[0m'".format(path));


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


def Waybackrecon():
	system("cd {}".format(path));
	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING WAYBACKMACHINE FOR RESOLVED SUBDOMAINS \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/domainsall.txt|waybackurls > {}/waybackdata/waybackmachine.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACKMACHINE DONE AT: {}/waybackdata/waybackmachine.txt  \e[0m'".format(path));

	#Interesting FILES FROM waybackmachine #
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING DESIRED WAYBACK FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | awk '/.sql$/;/.sql\?/;/.git$/;/.pdf$/;/.csv$/;/.csv\?/;/.deb$/;/.conf/;/admin/;/login/;/dashboard/;/.json$/;/.txt$/;/.xml$/;/woff/;/svg$/;/theme/;/eot/;/ttf/;/@/;/twitter/;/facebook/;/github/;/javascript/;/ref=/;/\?src/;/src/;/href/;/href\?/;/redirect/;/\?=/;/\?id=/;/file\=/;/page\=/;/content\=/;/source\=/;/.zip$/;/.tar$/;/.Tpl/;/.gz$/;/.rar$/;/.7z$/;/.pl$/;/.gz.zip$/'|sort -u > {}/waybackdata/waybackdesired.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK DESIRED DONE AT: {}/waybackdata/waybackmachine.txt  \e[0m'".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING PHP FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | awk '/.php$/;/.php\?/'|sort -u > {}/waybackdata/waybackphp.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK PHP DONE AT: {}/waybackdata/waybackphp.txt  \e[0m'".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING JSP FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | awk '/.jsp$/;/.jsp\?/' | sort -u >  {}/waybackdata/waybackjsp.txt 2> /dev/null".format(path,path));
	system("echo '\033[91m  Desired Wayback Saved to waybackjsp.txt!~  \e[0m'");
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK JSP DONE AT: {}/waybackdata/waybackjsp.txt  \e[0m'".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING ASP FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | awk '/.asp$/;/.asp\?/' |sort -u > {}/waybackdata/waybackasp.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK ASP DONE AT: {}/waybackdata/waybackasp.txt  \e[0m'".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING ASPX FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | awk '/.aspx$/;/.aspx\?/' |sort -u > {}/waybackdata/waybackaspx.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK ASPX DONE AT: {}/waybackdata/waybackaspx.txt  \e[0m'".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING JAVASCRIPT FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | awk '/.js$/;/.js\?/'| sort -u > {}/waybackdata/javascriptfiles.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK JAVASCRIPT DONE AT: {}/waybackdata/javascriptfiles.txt  \e[0m'".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING KEYVALUES PARAMETERS FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | sort -u|unfurl --unique keys  > {}/waybackdata/paramlist.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK KEYVALUES PARAMETERS DONE AT: {}/waybackdata/paramlist.txt  \e[0m'".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING PATHS FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | sort -u| unfurl --unique paths > {}/waybackdata/pathlist.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK PATHS DONE AT: {}/waybackdata/pathlist.txt  \e[0m'".format(path));

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DISCOVERING KEYPAIRS FROM WAYBACKMACHINE \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/waybackmachine.txt | sort -u| unfurl --unique keypairs |sed 's/www\.//g'  >> {}/waybackdata/keypairs.txt 2> /dev/null".format(path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  WAYBACK KEYPAIRS DONE AT: {}/waybackdata/keypairs.txt  \e[0m'".format(path));


###################################################################################
#############################FUNCTION COMPLETE#####################################
###################################################################################



def Jsdownload():
	system("cd {}".format(path));
	#Downloading The javascriptfiles#
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DOWNLOADING JAVASCRIPT FILES \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/waybackdata/javascriptfiles.txt|xargs -P {} -I{{}} sh -c 'cd {}/jsfiles/ && wget --no-check-certificates --timeout=3 --tries=2 {{}} ' > /dev/null 2>&1".format(path,threadings,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  DOWNLOADING JAVASCRIPT FILES DONE  \e[0m'");
	system("cd {}/jsfiles".format(path));
	system("rename 's/^-//g' -- *");
	system("cd {}".format(path));





###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################



def Jsextract():
	system("cd {}".format(path));
	#javascript beautify#
	system("ls {}/jsfiles/ > {}/listforurlextract.txt".format(path,path));
	######
	system("mkdir {}/jsfiles/js-beautify".format(path));
	system("mkdir {}/jsfiles/js-beautify/URLS".format(path));
	system("mkdir {}/jsfiles/js-beautify/URLS/relative".format(path));
	system("mkdir {}/jsfiles/js-beautify/URLS/linkfinder".format(path));
	###############

	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  RELATIVE URL EXTRACTOR STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	# Relative URL Extract #
	system("cd {}".format(path));
	system("cat {}/listforurlextract.txt|xargs -P {} -I{{}} sh -c 'ruby /Scripts/relative-url-extractor/extract.rb {}/jsfiles/{{}} >> {}/jsfiles/js-beautify/URLS/relative/relative.txt && echo \"---------------------\" >> {}/jsfiles/js-beautify/URLS/relative/relative.txt ' 2> /dev/null".format(path,threadings,path,path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  RELATIVE URL EXTRACTOR DONE  \e[0m'");
	#---------------------------------------#
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  JAVASCRIPT LINKFINDER STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	# LinkFinder URL Extraction #
	system("cd {}".format(path));
	system("cat {}/listforurlextract.txt|xargs -P {} -I{{}} sh -c 'python /Scripts/LinkFinder/linkfinder.py -i {}/jsfiles/{{}} -o cli >> {}/jsfiles/js-beautify/URLS/linkfinder/linkfinder.txt && echo \"---------------------\" >> {}/jsfiles/js-beautify/URLS/linkfinder/linkfinder.txt ' 2> /dev/null".format(path,threadings,path,path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  JAVASCRIPT LINKFINDER END \e[0m'");
	#-----------------------------------------#


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


def BeautifyJS():
	system("echo '\n'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  JS BEAUTIFY STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/listforurlextract.txt|xargs -P {} -I{{}} sh -c 'js-beautify -- {}/jsfiles/{{}} > {}/jsfiles/js-beautify/{{}} ' 2> /dev/null".format(path,threadings,path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  JS BEAUTIFY DONE  \e[0m'");


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################

#--------------------------------------#
'''
def Githubrecon():
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  GITHUB RECON GITROB STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("gitrob -github-access-token 016de8184894f75abd0838093cd1ddbb55e4f375 -threads 100 -save {}/OSINT/gitrob-{}.json {} > /dev/null 2>&1".format(path,program,program));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  GITROB END : {}/OSINT/gitrob-{}.json  \e[0m'".format(path,program));
'''
#-------------------------------------------


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


def Jenkins():
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  SHODAN JENKINS RECON STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("php /Scripts/jenkins-shell/shodan.php {}|awk '/^200 =/;/^Current/' | tee {}/DOMAINSFINAL/jenkins.txt 2> /dev/null".format(program,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  SHODAN JENKINS RECON END  : {}/DOMAINSFINAL/jenkins.txt  \e[0m'".format(path));


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


def Nmapscan():
	system("cd {}".format(path));
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  NMAP SCAN STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	#system("cat {}/DOMAINSFINAL/domainsall.txt|xargs -P {} -I{{}} sh -c 'nmap -sV -T3 -Pn -p80,81,113,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017,20,21,22,23,25,53,69,389,5900,5901,5902,3306,1433,1434,1234,4000,2076,2075,6443,3868,3366,5432,15672,9999,161,4044,7077,4040,8089,7447,7080,5673,7443,19000,19080 {{}} -oN {}/DOMAINSFINAL/NMAP/nmap-report-{{}}.txt > /dev/null 2>&1'".format(path,threadings,path));
	system("cat {}/DOMAINSFINAL/domainsall.txt|xargs -P {} -I{{}} sh -c 'masscan -p0-65535 $(dig +short {{}} ) -oL {}/DOMAINSFINAL/NMAP/nmap-report-{{}}.txt --rate 10000 2> /dev/null'".format(path,threadings,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  NMAP SCAN ENDED   \e[0m'");
	



###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################


def Sourcerecon():
	
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  PATHS PROBING & DOWNLOADING  (MEG) \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("meg {}/waybackdata/pathlist.txt {}/DOMAINSFINAL/headerdoms.txt {}/DOMAINSFINAL/meg".format(path,path,path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  PATH PROBING & DOWNLOAD ENDED   \e[0m'");

	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  FETCHING URLS,PARAMETERS,PATHS,DOMAINS FROM SOURCES (MEGURL) \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));

	system("cd {}/DOMAINSFINAL/meg".format(path));# VERY IMPPORTANT to GO TO THAT DIRECTORY

	system("gf urls|sort -u|uniq | grep -a {} >> {}/waybackdata/sourceurls.txt".format(domain,path));
	system("cat {}/waybackdata/sourceurls.txt | sort -u| uniq | unfurl --unique paths >> {}/waybackdata/pathlist.txt".format(path,path));
	system("cat {}/waybackdata/sourceurls.txt | sort -u| uniq | unfurl --unique keys >> {}/waybackdata/paramlist.txt".format(path,path));
	system("cat {}/waybackdata/sourceurls.txt | sort -u| uniq | unfurl --unique domains >> {}/waybackdata/domains.txt".format(path,path));
	
	system("cat {}/waybackdata/sourceurls.txt |sort -u > {}/waybackdata/sourceurlsuniq.txt".format(path,path));
	system("cat {}/waybackdata/pathlist.txt | sort -u > {}/waybackdata/pathlistuniq.txt".format(path,path));
	system("cat {}/waybackdata/paramlist.txt | sort -u > {}/waybackdata/paramlistuniq.txt".format(path,path));
	system("cat {}/waybackdata/domains.txt | sort -u > {}/waybackdata/domainsuniq.txt".format(path,path));

	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  SOURCE RECON ENDED    \e[0m'");



###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################
def Dirsearch():
	system("cd {}".format(path));
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DIRSEARCH MAIN STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("python3 /Scripts/dirsearch/dirsearch.py -u https://{} -t {} -e *".format(domain,dirsearchthreads));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  DIRSEARCH MAIN ENDED   \e[0m'");


###################################################################################
#####################FUNCTION COMPLETE############################################
###################################################################################

def Dirsearchsubs():
	system("cd {}".format(path));
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  DIRSEARCH STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/domainsall.txt|xargs -P {} -I{{}} sh -c 'python3 /Scripts/dirsearch/dirsearch.py -u https://{{}} -t {} -e php,aspx,jsp,html,jar,zip,json,tar,gzip,sql' > /dev/null 2>&1".format(path,threadings,dirsearchthreads));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  DIRSEARCH ENDED   \e[0m'");
#Must do this after resource recon(MEG)

#######################################################################
########################Modes Of recon Started######################
#####################################################################


def Cleandirsearch():
	system("cd {}".format(path));
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  CLEANING DIRSEARCH STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("ls /Scripts/dirsearch/reports/{} |grep -vi '.old'| while read line;do mv /Scripts/dirsearch/reports/{}/$line /Scripts/dirsearch/reports/{}/$line.old;done > /dev/null 2>&1".format(domain,domain,domain));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  CLEANING DIRSEARCH ENDED   \e[0m'");


#######################################################################
########################Modes Of recon Started######################
#####################################################################


def Cleandirsearchsubs():
	system("cd {}".format(path));
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo '\033[91m  CLEANING DIRSEARCHSUBS STARTED \e[0m'");
	system("echo '\033[92m =========================================================== \e[0m'");
	system("echo 'start: {} \n'".format(datetime.datetime.now().time()));
	system("cat {}/DOMAINSFINAL/domainsall.txt | sort -u | while read line;do ls /Scripts/dirsearch/reports/$line/ | grep -vi '.old' | while read i;do mv /Scripts/dirsearch/reports/$line/$i /Scripts/dirsearch/reports/$line/$i.old;done;done > /dev/null 2>&1".format(path));
	system("echo 'End: {} \n\n'".format(datetime.datetime.now().time()));
	system("echo '\033[91m  CLEANING DIRSEARCHSUBS ENDED   \e[0m'");



#######################################################################
########################Modes Of recon Started######################
#####################################################################


def Nosubs():
	_init_();
	Osint();
	Cleandirsearch();
	Dirsearch();

def Subs():
	_init_();
	Osint();
	Cleandirsearch();
	Dirsearch();
	Subdomains_discovery();
	Subdomain_sort();
	Takeover();
	Aquatone();
	Cleamtemp();


def Discover():
	CloudS3();
	Waybackrecon();
	Jsdownload();
	Jsextract();
	Jenkins();

def Fuzz():
	Sourcerecon();
	Cleandirsearchsubs()
	Dirsearchsubs();

def Network():
	Nmapscan();


def All():
	_init_();
	Osint();
	Cleandirsearch();
	Dirsearch();
	Subdomains_discovery(); 
	Subdomain_sort();
	Takeover();
	

	CloudS3();
	Waybackrecon();
	Jsdownload();
	Jsextract();
	Jenkins();
	
	Aquatone();
	Cleandirsearchsubs();
	Dirsearchsubs();

	Nmapscan();
	Cleamtemp();

def Beautify():
	BeautifyJS();

def Default():
	print(" No Such Mode Available \n");
	print(" Refer to help for more information ");
	sys.exit(0);

def main():
# construct the argument parse and parse the arguments
	banner();
	modes={
		"Subs":Subs,
		"Discover":Discover,
		"Fuzz":Fuzz,
		"Network":Network,
		"All":All,
		"Nosubs":Nosubs,
		"Beautify":Beautify,
		"default":Default
		}
	argp = argparse.ArgumentParser();
	argp.add_argument("-d", "--domain", required=True, help="Name of the domain e.g google.com");
	argp.add_argument("-p", "--program", required=True, help="Name of the program only e.g. google");
	argp.add_argument("-m", "--mode", required=True, help="Mode information (Subs, Nosubs,  Discover, Fuzz, Network, Beautify, All)");
	argp.add_argument("-t", "--threads", help="No of threads to run");
	args = vars(argp.parse_args());
	
	global domain;
 	global path;
 	global program;
 	domain=args["domain"];
 	program=args["program"];
 	path="~/recon/{}/{}".format(domain,datetime.date.today());
 	modes.get(args["mode"],Default)();
 	system("echo 'RECON ENDED : {} \n'".format(datetime.datetime.now().time()));
if __name__ == '__main__':main()