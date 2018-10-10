# coding: utf-8
import urllib
from bs4 import BeautifulSoup

SUFFIX_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
ICANN_URL = "https://newgtlds.icann.org/en/program-status/delegated-strings"


# htmlを抽出する
def get_soup(url):
    html = urllib.request.urlopen(url)
    soup = BeautifulSoup(html, "html.parser")

    return soup

# # TLDのリストを作成する（多すぎ）
# def make_list():
#     res = get_soup(SUFFIX_URL).text.split("\n")
#     tmp = [suffix for suffix in res if suffix != ""]
#     tld_list = [suffix if "*" not in suffix else suffix.split(".")[-1] for suffix in tmp if suffix[0] != "/"]
#
#     return tld_list

# ICANN公式からnew gTLDのリストを抜いてくる
# むしろnew gTLDに絞ってチェックした方が良いのかもしれない（悪用率が高いため）
def make_new_gtld(url):
    new_gtld = []
    soup = get_soup(url)
    for i, tld in enumerate(soup.find_all("td")):
        if i % 2 == 1:
            if not tld.find("span"):
                tld = str(tld.text)
            else:
                tld = str(tld.contents[1])
            if "xn--" in tld:
                tld = [i for i in tld.split(" ") if "xn--" in i][0]
                if "(" in tld:
                    tld = tld[tld.find("(") + 1: tld.find(")")]
            if "xn―cg4bki" in tld: # ICANN公式がtypoしているという、、
                tld = "xn--cg4bki"
            tld = tld.lower()
            new_gtld.append(tld)

    return new_gtld

# TLDを付け替える
def generate_domain(domain):
    tld_list = make_new_gtld(ICANN_URL)
    # if "www." in domain:
    #     domain = "www." + domain.split(".")[1]
    # else:
    #     domain = domain.split(".")[0]

    # 単純にTLDだけを付け替える実装にする（co.jp　→ co.xyz）
    check_list = [".".join(domain.split(".")[:-1]) + "." + tld for tld in tld_list]

    return check_list

def near_urls(domain):
    return generate_domain(domain)

if __name__  == "__main__":
    check_list = generate_domain("www.example.com")
    print(check_list)
    print(len(check_list))
