from WebConfig import web
from Logging import log as Log
from urllib.parse import urlparse, urljoin

f = open("FileInclusion/fileic.txt", "r")
payloads = []
for pay in f.readlines():
    payloads.append(pay.strip())

KEYS_WORDS = ["root:x:0:0", "root:/root:", "daemon:x:1:", "daemon:x:2", "bin:x:1:1"
    , "/bin/bash", "/sbin/nologin", "man:x:", "mail:x:", "games:x:", "Nobody:"
    , "MySQL Server", "gnats:x:", "www-data:x:", "/usr/sbin/", "backup:x:"]




def find_key_words(html):
    for key_word in KEYS_WORDS:
        if key_word in html:
            return True
    return False


def scaner_file_inclusion(url, vulnerable_url):
    queries = urlparse(url).query
    Log.info("scan file inclusion : " + url)
    if queries != '':
        for payload in payloads:
            # chèn payload vào query trong các url tồn tại query 
            parser_query = []
            for query in queries.split("&"):
                parser_query.append(query[0:query.find('=') + 1])
            new_query = "&".join([param + payload for param in parser_query])
            new_url = url.replace(queries, new_query, 1)
            # sử dụng để gộp url
            source = web.getHTML(new_url)
            if source:
                if find_key_words(source.text) or (200 <= source.status_code <= 299):
                    Log.high(Log.R + ' Vulnerable detected in url :' + new_url)
                    vulnerable_url.append([new_url, 'url/href', 'file inclution', payload])
                    return True

        return False
