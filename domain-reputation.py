#!/usr/bin/python
'''
What does this do?
	#Checks a domain's whois info
How you want to use it: (provide a domain name for the argument print these parsed results)
		print "[+]   Retrieved WHOIS information for <domain>
		Created date
		expiration date
Next iteration(s)
	Retrieve Virustotal info for the same domain

NO FUNCTIONS YET.  GETTING IT TO WORK WITH A PRE-DEFINED DOMAIN
'''
import pythonwhois, re, sys, requests

domain = 'n1cfury.com'
APIKEY_VIRUSTOTAL = '### PASTE API KEY HERE ###'

#WHOIS QUERY								
domain_query = pythonwhois.get_whois(domain)

'''
#VIRUSTOTAL QUERIES
#Submits a site to Virustotal (USE THIS FOR NEW SITES)
params = {'apikey': APIKEY_VIRUSTOTAL, 'url': domain}
response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
vts_response = response.json()
'''

#Retrieving results
import requests
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




'''