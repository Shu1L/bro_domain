import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import quote
import time
import urllib3
import sys
import argparse
import fire
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



lxr_rule = '<div.*>联系人</div><div class="fr WhLeList-right block ball lh24"><span>(.*?)</span>'
yx_rule='<div class="fl WhLeList-left">联系邮箱</div><div class="fr WhLeList-right block ball lh24"><span>(.*?)</span>'
phone_rule='<div class="fl WhLeList-left">联系电话</div><div class="fr WhLeList-right block ball lh24"><span>(.*?)</span>'
houzui_lists = ['cn', 'com', 'com.cn', 'org', 'net', 'cc']
ipc_headers = {
                "Host": "m-beian.miit.gov.cn",
                "Origin": "https://m-beian.miit.gov.cn",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                "Referer": "https://m-beian.miit.gov.cn/",
                "Accept-Language": "zh-cn",
                "Pragma": "no-cache",
                "Cache-Control": "no-cache",
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "keep-alive"
            }
chinaz_headers={
        "Host": "whois.chinaz.com",
        "Accept-Encoding": "Accept-Encoding: gzip, deflate",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36",
        "Referer": "http://whois.chinaz.com/",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cache-Control": "no-cache",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "close"
}


domain_lists=[]


class brodomain_spider(object):
    def __init__(self,domain,proxy=None):
        self.domain=''
        self.keywords=''
        self.houzui_lists=['com','cn','net','com.cn','cc','org']
        self.proxy=proxy

    def icp_query(self,domain):
            print('开始备案查询....')
            html = requests.get("http://icp.chinaz.com/{}".format(domain)).text
            icp = re.findall('<p><font>(.*?)-.*</font>', html)
            keywords="".join(icp)
            url = "https://m-beian.miit.gov.cn/webrec/queryRec"
            query_word=keywords
            encode_cpy = quote(query_word,encoding='utf-8')
            params ="keyword={}&pageIndex=1&pageSize=20".format(encode_cpy)
            res = requests.post(url=url, data=params, headers=ipc_headers, verify=False)
            res_json = res.json()
            total_page = res_json["result"]["totalPages"]
            content = res_json["result"]["content"]
            if not content:
                return
            for item in content:
                domain = item["domain"]
                domain_lists.append(domain)
            for page in range(2, int(total_page) + 1):
                params_page = "keyword={}&pageIndex={}&pageSize=20".format(encode_cpy, page)
                with requests.post(url, data=params_page, headers=ipc_headers, verify=False) as r:
                    if r.status_code != 200:
                        return
                    res_json = r.json()
                    content = res_json["result"]["content"]
                    if not content:
                        return
                    for item in content:
                        domain = item["domain"]
                        domain_lists.append(domain)



    def whois_query(self,domain):
        url=domain.split('.')[0]
        for houzui in self.houzui_lists:
            whois_url=url+"."+houzui
            print('开始whois反查....')
            html=requests.get("http://whois.chinaz.com/{}".format(whois_url)).text
            lxr=re.findall(lxr_rule,html)
            yx=re.findall(yx_rule,html)
            phone=re.findall(phone_rule,html)
            if lxr:
                encode_lxr=quote("".join(lxr))
                whois_lxr=requests.get("http://whois.chinaz.com/reverse?host={}&ddlSearchMode=2".format(encode_lxr))
                whois_lxr_html=whois_lxr.text
                num_jilu=re.findall('<i class="col-blue02">(.*?)</i>',whois_lxr_html)
                num_jilu="".join(num_jilu)
                try:
                    num_jilu=int(num_jilu)
                except:
                    continue
                if int(num_jilu)<1000:
                    for i in range(1,int(int(num_jilu)/20+1)):
                        whois_lxr = requests.get("http://whois.chinaz.com/reverse?host={0}&ddlSearchMode=2&page={1}".format(encode_lxr,str(i)))
                        whois_lxr_html = whois_lxr.text
                        whois_lxr_domains=re.findall('<div class="listOther"><a href="/.*?" target="_blank">(.*?)</a></div>',whois_lxr_html)
                        for i in whois_lxr_domains:
                            domain_lists.append(i)
                        time.sleep(1)

            if yx:
                str_yx = "".join(yx)
                whois_yx = requests.get("http://whois.chinaz.com/reverse?host={0}&ddlSearchMode=1&domain={1}".format(str_yx,url))
                whois_yx_html = whois_yx.text
                num_jilu = re.findall('<i class="col-blue02">(.*?)</i>', whois_yx_html)
                num_jilu = "".join(num_jilu)
                try:
                    num_jilu=int(num_jilu)
                except:
                    continue
                if int(num_jilu)<1000:
                    for i in range(1,int(int(num_jilu) / 20+1)):
                        whois_yx = requests.get("http://whois.chinaz.com/reverse?host={0}&ddlSearchMode=1&domain={1}&page={2}".format(str_yx, url,str(i)))
                        whois_yx_html = whois_yx.text
                        whois_yx_domains=re.findall('<div class="listOther"><a href="/.*?" target="_blank">(.*?)</a></div>',whois_yx_html)
                        for i in whois_yx_domains:
                            domain_lists.append(i)
                        time.sleep(1)


            if phone:
                str_phone = "".join(phone)
                whois_phone = requests.get("http://whois.chinaz.com/reverse?host={0}&ddlSearchMode=3&domain={1}".format(str_phone,whois_url))
                whois_phone_html = whois_phone.text
                num_jilu = re.findall('<i class="col-blue02">(.*?)</i>', whois_phone_html)
                num_jilu = "".join(num_jilu)
                try:
                    num_jilu=int(num_jilu)
                except:
                    continue
                if int(num_jilu)<1000:
                    for i in range(1,int(int(num_jilu) / 20+1)):
                        whois_phone = requests.get("http://whois.chinaz.com/reverse?host={0}&ddlSearchMode=1&domain={1}&page={2}".format(str_phone,url,str(i)))
                        whois_phone_html = whois_phone.text
                        whois_phone_domains=re.findall('<div class="listOther"><a href="/.*?" target="_blank">(.*?)</a></div>',whois_phone_html)
                        for i in whois_phone_domains:
                            domain_lists.append(i)
                        time.sleep(1)
            time.sleep(3)
        save_result(domain,domain_lists)




def save_result(domain, domain_lists):
    bro_lists=set(domain_lists)
    for line in bro_lists:
        print(line)
    with open(domain + '.txt', 'w') as w:
        for line in bro_lists:
            w.write(line + '\n')


def run(domain):
    main=brodomain_spider(domain)
    main.icp_query(domain)
    main.whois_query(domain)



if __name__ == '__main__':
    fire.Fire(run)

