from homograph_dic import hword
import tldextract

def create_homo_domain(thd,sd,td,puny):

    result = []
    sum = 0
    for i in range(len(sd)):
        if sd[i] in hword.keys():
            #対象の文字が辞書に入っているか確認
            for h in hword[sd[i]]:
                d = list(sd)
                d[i] = h                 #文字を入れ替える
                v = ''.join(d)
                if puny != "punycode":
                    x = thd + "." + v + "." +td
                    result.append(x)
                elif puny == "punycode":
                    v = str(v.encode("idna"),"utf-8") #punycode表記
                    x = thd + "." + v + "." +td
                    result.append(x)

    if thd == "" :
        for i in range(len(result)):
            result[i]=result[i][1:]
    
    
    return result


def near_urls(domain,puny):
    homo_domain=[]
    
    if "http://" in domain:
        domain=domain.replace("http://","")

    if "https://" in domain:
        domain=domain.replace("https://","")

    
    ext = tldextract.extract(domain)
    thd = ext.subdomain
    sd = ext.domain
    td = ext.suffix

    homo_domain = create_homo_domain(thd,sd,td,puny)

    return homo_domain


if __name__ == '__main__':

    a = near_urls("google.com","")
    #第二引数が"punycode"の場合、punycode表記で返す

    print(len(a))
    
