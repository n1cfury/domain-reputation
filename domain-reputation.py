#TODO:  Parse the data to make the output look neater

import pythonwhois, senderbase, re, sys, requests			#Third party modules that require pip install
from senderbase import SenderBase

domain = sys.argv[1]
APIKEY_VIRUSTOTAL = 'PUT VIRUSTOTAL API KEY HERE'

usage = "python domain-reputation.py <domain name> "

def banner():
	print "################################################################"
	print "###############	  Domain Reputation tool	###############"
	print "###############		by n1cFury	        ###############"
	print "################################################################"

#WHOIS QUERY	
def WhoisQuery(domain):							
	domain_query = pythonwhois.get_whois(domain)
	print ""
	print "[+]               WHOIS Report for "+domain+" completed......"
	print ""
	print domain_query
	print "##############################################################################"

#VIRUSTOTAL QUERIES
def VirTotalQuery(domain):
	headers = {
	  "Accept-Encoding": "gzip, deflate",
	  "User-Agent" : "gzip,  My Python requests library example client or username"
	  }
	params = {'apikey': APIKEY_VIRUSTOTAL, 'resource': domain}
	response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
	  params=params, headers=headers)
	vtr_response = response.json()
	print "[+]               Virustotal retrieved results for "+domain+" ..............."
	print ""
	print vtr_response
	print "##############################################################################"

#SENDERBASE QUERIES
def SBaseQuery(domain):
	sb = SenderBase(timeout=30)
	sb_result = sb.lookup(domain)
	print "[+]               Senderbase retrived results for "+domain+" ............"
	print ""
	print sb_result
	print "##############################################################################"

def main():
	if len(sys.argv) == 1:
		banner()
		WhoisQuery(domain)
		VirTotalQuery(domain)
		SBaseQuery(domain)
	else:
		print usage

if __name__ == "__main__":
  main()
