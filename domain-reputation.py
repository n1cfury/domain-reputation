#!/usr/bin/python
'''
What does this do?
	#Checks a domain's reputation from multiple sources
How the output should look: (repeat for each service e.g. whois, virustotal, etc )
		print "[+]   Retrieved <service> information for <domain>"
		<parsed results>
		
Next iteration(s)
	Parsing the output and make it neater


'''
import pythonwhois, senderbase 					#Third party modules that require pip install
from senderbase import SenderBase
import re, sys, requests


domain = 'n1cfury.com'
APIKEY_VIRUSTOTAL = '### VIRUSTOTAL API KEY ###'

#WHOIS QUERY								
domain_query = pythonwhois.get_whois(domain)
print "[+] Report for "+domain+" completed......"
print ""

#VIRUSTOTAL QUERIES
#Submits a site to Virustotal (USE THIS FOR NEW SITES)
params = {'apikey': APIKEY_VIRUSTOTAL, 'url': domain}
response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
vts_response = response.json()
print "[+] Virustotal submittal for "+domain+" has completed..........."
print vts_response


#Retrieving results
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"
  }
params = {'apikey': APIKEY_VIRUSTOTAL, 'resource': domain}
response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
  params=params, headers=headers)
vtr_response = response.json()
print "[+] Virustotal retrieved results for "+domain+" ..............."
print vtr_response


#SENDERBASE QUERIES
sb = SenderBase(timeout=30)
sb_result = sb.lookup(domain)
print "[+] Senderbase retrived results for "+domain+" ............"
print sb_result






