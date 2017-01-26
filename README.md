# domain-reputation
This tool is used to gather reputation information from multiple sources.  This may be useful for gathering information on questionable sites..  

What you'll need for this tool:
Additional modules you'll need to install:  senderbase, virustotal
Both of these modules are pip installable
	sudo python pip install senderbase
	sudo python pip install virustotal


So far I have three sources set up.  I'm in the process of making the output neater (i.e. parsing)

	WHOIS:  	I will likely find another source (probably senderbase) that has this information included
	
	VIRUSTOTAL: 	There are many queries you can make, but for this tool I'm sticking with reputation by domain
			The query will have either an option to submit a query, or retrive an existing one.  For the 
			sake of the API, run this against pre-existing queries.
	
	SENDERBASE: 	This is primarily used for email domains
