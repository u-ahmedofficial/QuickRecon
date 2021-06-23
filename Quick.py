from os import system
from sys import argv
import sys
import os
import argparse
import datetime
"""
This is my fucking
"""
domain='';
program='';
path='';
def Report():
	system("cd {} && ls out-* |while read a;do cp {}/$a {}/Output/ && echo $a | aha --black --title 'Report' > {}/Report/$a.html 2> /dev/null && cat {}/$a | aha --black --title 'Report' >> {}/Report/$a.html 2> /dev/null;done".format(path,path,path,path,path,path));

def main():
	
	argp = argparse.ArgumentParser();
	argp.add_argument("-d", "--domain", required=True, help="Name of the domain e.g google.com");
	argp.add_argument("-p", "--program", required=True, help="Name of the program only e.g. google");
	argp.add_argument("-m", "--mode", required=True, help="Mode information (Subs, Nosubs,  Discover, Fuzz, Network, All)");
	argp.add_argument("-t", "--threads", help="No of threads to run");
	args = vars(argp.parse_args());
	system("echo 'RECON Started: {}'".format(datetime.datetime.now().time()));
	global domain;
 	global path;
 	global program;
 	domain=args["domain"];
 	program=args["program"];
 	path="~/recon/{}".format(domain);
 	if not os.path.exists("~/recon"):
		system("mkdir ~/recon");

	if not os.path.exists(path):
		system("mkdir {}".format(path)); 

	if not os.path.exists("{}/{}".format(path,datetime.date.today())):
		system("mkdir {}/{}".format(path,datetime.date.today())); 
	path="~/recon/{}/{}".format(domain,datetime.date.today());

	system("python /Scripts/recon.py -d {} -m {} -p {} | tee {}/out-{} 2>&1".format(args["domain"],args["mode"],args["program"],path,datetime.date.today()));
	Report();

	system("echo 'RECON ENDED: {}'".format(datetime.datetime.now().time()));
if __name__ == '__main__':main()
