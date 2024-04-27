from urllib.parse import urlparse, urljoin, urlencode, parse_qs

from bs4 import BeautifulSoup
import time
from Logging import log as Log
from Logging import progressBar
from SQLi import sqlerrors
from WebConfig import web

f = open("SQLi/sql.txt", "r")
payloads = []
for pay in f.readlines():
    payloads.append(pay.strip())


def scan_sql_error_base_in_form(url, vulnerable_url):
    html = web.getHTML(url)
    ## lấy giá trị được trả về từ module request

    if html:
        soup = BeautifulSoup(html.text, 'html.parser')
        forms = soup.find_all('form', method=True)
        Log.info('request : ' + url + " in form with action")


        for form in forms:
            try:
                action = form['action']
            except KeyError:
                action = url
            try:
                method = form['method'].lower().strip()
            except KeyError:
                method = 'get'
            i = 0
            for payload in payloads[:30]:
                keys = {}
                for key in form.find_all(["input", "textarea"]):
                    try:
                        if key['type'] == 'submit':
                            try:
                                keys.update({key['name']: key['name']})
                            except Exception as e:
                                keys.update({key['value']: key['value']})
                        else:
                            keys.update({key['name']: payload})
                    except Exception as e:
                        Log.error("Internal error " + str(e))

                final_url = urljoin(url, action)
                Log.info('target url/form : ' + final_url)
                if method == 'get':
                    source = web.getHTML(final_url, method=method, params=keys)
                    vulnerable, db = sqlerrors.check(source.text)
                    if vulnerable and (db is not None):
                        vulnerable_url.append([final_url, 'form','sqli', payload])
                        Log.high(Log.R + ' Vulnerable deteced in url/form :' + final_url + ']')
                        
                        break
                elif method == 'post':
                    source = web.getHTML(final_url, method=method, data=keys)
                    vulnerable, db = sqlerrors.check(source.text)
                    if vulnerable and (db is not None):
                        vulnerable_url.append([final_url, 'form','sqli', payload])
                        Log.high(Log.R + ' Vulnerable deteced in url/form :' + final_url)
                        
                        break
                progressBar.progressbar(i + 1,30,prefix = 'Progress:', suffix = 'Complete', length = 50)
                i +=1




def scan_sql_error_base_in_url(url, vulnerable_url):




    Log.info('target url : ' + url)

    queries = urlparse(url).query
    i = 0
    if queries != '':
        for payload in payloads:
              # lấy phần queries trong url ra

                parser_query = []               
                for query in queries.split("&"):
                    parser_query.append(query[0:query.find('=') + 1])                
                new_query = "&".join([param + payload for param in parser_query])                
                final_url = url.replace(queries, new_query, 1)
                encode_query = urlencode({x: payloads for x in parse_qs(queries)})
                final_encode_url = url.replace(queries, encode_query, 1)            
                res = web.getHTML(final_encode_url)

                if res:
                   
                    vulnerable2, db2 = sqlerrors.check(res.text)
                    if vulnerable2 and (db2 is not None):
                        Log.high(Log.R + ' Vulnerable sqli deteced in url :' + final_url)
                        vulnerable_url.append([final_url, 'url/href','sqli', payload])
                        progressBar.progressbar(30, 30, prefix='Progress:', suffix='Complete', length=0)
                        return True
                progressBar.progressbar(i + 1,len(payloads), prefix='Progress:', suffix='Complete', length=50)
                i += 1
    else:
        return False
    return False






