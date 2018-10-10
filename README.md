# Install

1. `git clone https://github.com/toshs/domain-scanner.git`
2. `python3 setup.py install` or `pip3 install -e ./`

# Usage
## Generate domains
`dscan <domainname>`

## Generate and check domains with GET request
`dscan <domainname> --http`
### Result

	generating qr ...
	generated: 49
	generating suffix ...
	generated: 1225
	generating bit ...
	generated: 68
	generating typo ...
	generated: 78
	fetching domain info ...
	100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:02<00:00,  1.05it/s]
	[
	    {
	        "domain_name": "aoogle.com",
	        "generate_type": [
	            "qr"
	        ],
	        "http_status_code": 200
	    },
	    {
	        "domain_name": "google.charity",
	        "generate_type": [
	            "suffix"
	        ],
	        "http_status_code": -1
	    },
		 ...
	]
	
## Generate and check domains with Virus Total
`dscan <domainname> --http --virustotal <here VirusTotal API key>`  
VERY SLOW.  
### Result
	
	generating qr ...
	generated: 49
	generating suffix ...
	generated: 1225
	generating bit ...
	generated: 68
	generating typo ...
	generated: 78
	fetching domain info ...
	100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:09<00:00,  2.89s/it]
	[
	    {
	        "domain_name": "aoogle.com",
	        "generate_type": [
	            "qr",
	            "typo"
	        ],
	        "http_status_code": 200,
            "virus_total": {
                "Safety score": 100,
                "Adult content": "no",
                "Verdict": "safe"
            }
	        "site_threat": []
	    },
	    ...
	]

## Generate and check domains with Google Safe Browsing
`dscan <domainname> --http --safe_site <here Google Safe Browsing API key>`
### Result
Empty `site_threat` means safe.  

	generating qr ...
	generated: 49
	generating suffix ...
	generated: 1225
	generating bit ...
	generated: 68
	generating typo ...
	generated: 78
	fetching domain info ...
	100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:09<00:00,  2.89s/it]
	[
	    {
	        "domain_name": "aoogle.com",
	        "generate_type": [
	            "qr",
	            "typo"
	        ],
	        "http_status_code": 200,
	        "site_threat": []
	    },
	    ...
	]


## Generate and check domains by resolving
`dscan <domainname> --ip`
### Result

	generating qr ...
	generated: 1
	generating suffix ...
	generated: 1
	generating bit ...
	generated: 1
	generating typo ...
	generated: 1
	fetching domain info ...
	100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4/4 [00:05<00:00,  1.63s/it]
	[
		{
			"generate_type": [
				"qr"
			],
			"domain_name": "aoogle.com",
			"ip": "23.253.58.227"
		},
		...
	]
