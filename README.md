# domain-scanner
自分が保有するドメイン名に類似したドメイン名の利用状況をチェックできるツールです。  

シードとなるドメイン名を与えると、以下のような類似ドメインを生成し、ドメイン名が使われているか、悪性かどうかなどをチェックします。  

* QRコードにおいて符号語が近いドメイン名
* タイプミスしやすいドメイン名(ex. google.com -> googlw.com)
* (通信路において)1bit反転するとなるドメイン名
* ハイフンで単語を繋げたドメイン名(ex. google.com -> google-recruit.com)
* 国際化ドメイン名で見間違いやすいドメイン名(ホモグラフドメイン、ex. kawasaki.com -> кawasaki.com 、kがキリル文字)

ドメインのチェックに使える項目は以下です。

* DNS: 名前解決の結果
* HTTP: ステータスコード
* VirusTotal: 悪性かどうかなど
* GoogleSafeSite: どんな脅威として報告されているか

# Install
1. `git clone https://github.com/toshs/domain-scanner.git`
2. `cd domain-scanner`
2. `python3 setup.py install` or `pip3 install -e ./`

# Usage
```
usage: dscan [-h] [-g] [--safe_site SAFE_SITE] [--virustotal VIRUSTOTAL]
             [--ip] [--debug] [--genlist GENLIST [GENLIST ...]] [--in_use]
             domain_name

positional arguments:
  domain_name

optional arguments:
  -h, --help            show this help message and exit
  -g, --http            Get http response by each candidate domains
  --safe_site SAFE_SITE
                        Get google safe sites tool information. must be
                        followed by api key
  --virustotal VIRUSTOTAL
                        Get VirusTotal tool information. must be followed by
                        api key. VERY SLOW
  --ip                  Get IP address for each candidate domains
  --debug               For debug. It restlicts the length of domain list.
  --genlist GENLIST [GENLIST ...]
                        Specify using generators as list.
  --in_use              It shows only domains in use.

```

## example
### Generate domains
`dscan <domainname>`

### Generate and check domains with GET request
`dscan <domainname> --http`
#### Result

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
	
### Generate and check domains with Virus Total
`dscan <domainname> --http --virustotal <here VirusTotal API key>`  
VERY SLOW.  
#### Result
	
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

### Generate and check domains with Google Safe Browsing
`dscan <domainname> --http --safe_site <here Google Safe Browsing API key>`
#### Result
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


### Generate and check domains by resolving
`dscan <domainname> --ip`
#### Result

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
