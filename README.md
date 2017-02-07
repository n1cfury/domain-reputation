# domain-reputation
This tool is used to gather reputation information from multiple sources.  This may be useful for gathering information on questionable sites..  

What you'll need for this tool:
Virustotal API Key: You can obtain a public API key by setting up an account on Virustotal

Additional modules you'll need to install:  senderbase, virustotal
Both of these modules are are installed using pip
	sudo python pip install senderbase
	sudo python pip install virustotal


So far I have three sources set up.  I'm in the process of making the output neater (i.e. parsing)

	WHOIS:  	I will likely change how this gathers WHOIS information.
	
	[VIRUSTOTAL](https://www.virustotal.com/): 	This will retrieve domains that have already been searched for the sake of the API.
	
	[SENDERBASE](http://www.senderbase.org/): 	This is primarily used for tracking reputation of mail domains.  
