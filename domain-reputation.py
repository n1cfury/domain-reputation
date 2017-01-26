#!/usr/bin/python
'''
What does this do?
	#Checks a domain's reputation from multiple sources
How the output should look: (repeat for each service e.g. whois, virustotal, etc )
		print "[+]   Retrieved <service> information for <domain>"
		<parsed results>
		
Next iteration(s)
	Start working on output

NO FUNCTIONS YET.  GETTING IT TO WORK WITH A PRE-DEFINED DOMAIN
'''
import pythonwhois, senderbase 					#Third party modules that require pip install
from senderbase import SenderBase
import re, sys, requests


domain = 'n1cfury.com'
APIKEY_VIRUSTOTAL = '### VIRUSTOTAL API KEY ###'

#WHOIS QUERY								
domain_query = pythonwhois.get_whois(domain)

'''
#VIRUSTOTAL QUERIES
#Submits a site to Virustotal (USE THIS FOR NEW SITES)
params = {'apikey': APIKEY_VIRUSTOTAL, 'url': domain}
response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
vts_response = response.json()


#Retrieving results
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"
  }
params = {'apikey': APIKEY_VIRUSTOTAL, 'resource': domain}
response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
  params=params, headers=headers)
vtr_response = response.json()
'''

#SENDERBASE QUERIES

sb = SenderBase(timeout=30)
my_result = sb.lookup(domain)


'''
#COMPLETE SCAN RESULTS
print "[+] Report for "+domain+" completed......"
print ""
print "[+] whois results for "+domain+ " ..........."
print domain_query
print ""
print "[+] Virustotal submittal for "+domain+" has completed..........."
print vts_response
print ""
print "[+] Virustotal retrieved results for "+domain+" ..............."
print vtr_response
print "[+] Virustotal retrieved results for "+domain+" ..............."
print vtr_response
print ""
print "[+] Senderbase retrived results for "+domain+" ............"

'''