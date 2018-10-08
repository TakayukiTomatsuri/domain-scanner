from combo_dic import post_word,pre_word,hyphen_word
import tldextract

def create_combo(thd,sd,td):

    c = []
    #sldの後に単語があるドメイン100個
    for i in post_word:
        v = sd + i
        c.append(thd+"."+v+"."+td)

    #sldの前に単語があるドメイン100個
    for j in pre_word:
        w = j + sd
        c.append(thd+"."+w+"."+td)

    #sldのあとにハイフンと単語があるドメイン100個
    for k in hyphen_word:
        x = sd + k
        c.append(thd+"."+x+"."+td)

    
    
    if thd == "":
        for y in range(len(c)):
            c[y] = c[y][1:]
        
    return c


def near_urls(domain):

    combo_domain=[]
    
    if "http://" in domain:
        domain=domain.replace("http://","")

    if "https://" in domain:
        domain=domain.replace("https://","")

    ext = tldextract.extract(domain)
    thd = ext.subdomain
    sd = ext.domain
    td = ext.suffix

    #comboドメインを300個生成
    combo_domain = create_combo(thd,sd,td)
    
    return combo_domain


if __name__ == '__main__':

    t = near_urls("www.mercari.com")

    print(t)
