import sys
import argparse
import copy

from dscanner import qr
from dscanner import suffix
from dscanner import bit
from dscanner import typo
from dscanner import homo
from dscanner import combo

import urllib.request
import urllib.error
import json
import socket 
from bs4 import BeautifulSoup
import socket
import urllib
from urllib.request import urlopen
from gglsbl import SafeBrowsingList
import time
from tqdm import tqdm

def fetch_pdns_domain_info(domain_name, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': domain_name, 'apikey': apikey}
    response = urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()

    response_dict = json.loads(response)
    return response_dict

def print_progress(progress_string):
    print(progress_string, file=sys.stderr)

def domain_filter_only_in_use(domains_dict_original):
    # Leave the original dict intact
    domains_dict = copy.deepcopy(domains_dict_original)
    for domain_name, domain_info in domains_dict_original.items():
        if "ip" in domain_info:
            if domain_info["ip"] != "":
                continue
        if "virus_total" in domain_info:
            if len(domain_info["virus_total"]) > 0:
                continue
        if "site_threat" in domain_info:
            if len(domain_info["site_threat"]) > 0:
                continue
        if "http_status_code" in domain_info:
            if domain_info["http_status_code"] != -1:
                continue
 
        del domains_dict[domain_name]

    return domains_dict

def main():
    # 引数の解釈の準備
    p = argparse.ArgumentParser()
    p.add_argument("domain_name")
    p.add_argument('-g', '--http', action="store_true", help="Get http response by each candidate domains")
    p.add_argument('--safe_site', default="", help="Get google safe sites tool information. must be followed by api key ")
    p.add_argument('--virustotal', default="", help="Get VirusTotal tool information. must be followed by api key. VERY SLOW ")
    p.add_argument('--ip', action="store_true", help="Get IP address for each candidate domains")
    p.add_argument('--debug', action="store_true", help="For debug. It restlicts the length of domain list.")
    # `$ dscan google.com --genlist qr typo` などとして使う
    p.add_argument('--genlist', nargs='+', help="Specify using generators as list.")
    p.add_argument('--in_use', action="store_true", help="It shows only domains in use.")
     
    args = p.parse_args()

    # URL候補を取得
    generator_dict = {}
    template_generator_names =  ["qr", "suffix", "bit", "typo", "homo", "combo"]
    generator_names = []
    # 使うgeneratorが指定された場合
    if not args.genlist is None:
        for generator_name in args.genlist:
            if generator_name in template_generator_names:
                generator_names.append(generator_name)
            else:
                print("error: \""+ generator_name +"\" is not generator name.", file=sys.stderr)
    else:
        generator_names = template_generator_names


    for generator_name in generator_names:
        print_progress("generating "+ generator_name  +" ...")
        list_slice = ""
        if args.debug:
           # in debug mode, length of domain list is restricted
           list_slice = "[:1]"        
        generator_dict[generator_name]     = eval(generator_name +".near_urls(args.domain_name)" + list_slice)
        print_progress("generated: " + str(len(generator_dict[generator_name])))

    print_progress("fetching domain info ...")

    # 辞書形式でドメインの情報らを持つ
    domains_dict = {}
    for generate_type_name, domain_list in generator_dict.items():
        for domain_name in domain_list:
            if domain_name not in domains_dict:
                domains_dict[domain_name] = {}
                # 冗長だがあとでjsonに変換するときに必要
                domains_dict[domain_name]["domain_name"] = domain_name
            
            if "generate_type" not in domains_dict[domain_name] :
                domains_dict[domain_name]["generate_type"] = []
            
            domains_dict[domain_name]["generate_type"].append(generate_type_name)

    # ドメインに関する情報を調べ、記録していく
    for domain_name, domain_info_dict in tqdm( domains_dict.items() ):            
            # httpレスポンス情報を付加する
            if args.http:
                http_status_code = 0
                try:
                    # 200番台のステータスコードを取得
                    http_status_code = urllib.request.urlopen("http://" + domain_name,
                                                              timeout=0.5).status
                except urllib.error.HTTPError as e:
                    # 200番台以外のステータスコードを取得
                    http_status_code = e.code
                # connection refusedなどになった場合。後でもっとうまく変えたほうがよいかも
                except urllib.error.URLError as e:
                    http_status_code = -1
                except socket.timeout:
                    http_status_code = -1
                except ConnectionResetError:
                    http_status_code = -1
                domain_info_dict["http_status_code"] = http_status_code

            # Google Safe Brawsingの情報を取得
            if len(args.safe_site)>0:
                api_key_gsb = args.safe_site
                sbl = SafeBrowsingList(api_key_gsb)
                threat_list = sbl.lookup_url(domain_name)
                if threat_list == None:
                    domain_info_dict["site_threat"] = []
                else: 
                    domain_info_dict["site_threat"] = threat_list

            # VirusTotalの情報を取得
            if len(args.virustotal)>0:
                api_key_vt = args.virustotal

                # TODO:関数とかに後でする
                interval_seconds_virustotal = 60/4
                retry_max_time = 2
                retry_sleep_seconds_virustotal = 1
                for _ in range(retry_max_time):
                    try:
                        info_virustotal = fetch_pdns_domain_info(domain_name, api_key_vt)
                    except:
                        # virustotalがrate limitなどなどで取得に失敗した場合はすこし待つ
                        time.sleep(retry_sleep_seconds_virustotal)
                    else:
                        try:
                            domain_info_dict["virus_total"] = info_virustotal["Webutation domain info"]
                        except KeyError:
                            domain_info_dict["virus_total"] = {}
                        # virustotalのrate limitにかからないように60/4 = 15秒ほど寝る
                        # 制限は1分間に4クエリなのだから、1クエリにつき15秒まつのではなく、4クエリ投げたら1分待つ方が正当だが面倒なのでこうした
                        time.sleep(interval_seconds_virustotal)
                        break

            if args.ip:
                try:
                    # 生成したドメインの IP アドレスを取得
                    ip = socket.gethostbyname(domain_name)
                except socket.gaierror:
                    ip = ''
                finally:
                    domain_info_dict["ip"] = ip

            # 追加例：
            # geoip情報を付加する
            # if args.geoip:
            #     domain_info_dict["geoip"] = country
    
    if args.in_use:
        domains_dict = domain_filter_only_in_use(domains_dict)    
   
    print_list = []
    for domain_info_dict in domains_dict.values():
        print_list.append(domain_info_dict)

    print(json.dumps(print_list, indent=4, separators=(',', ': ')) )

if __name__ == '__main__':
    main()
