import requests
import string
import random
import sys
import getopt

def usage():
    print("Usage: fuzzer.py [URL]")

if (len(sys.argv) != 2):
        usage()
        sys.exit(1)

base_url = sys.argv[1]
payload = "<script>alert(1)</script>;"
url = base_url + "?token=" + payload

res_base = requests.get(base_url)
res_fuzz = requests.get(url)

if (res_base.status_code == 200):
    print("GET OK")

    if res_fuzz.encoding is None:
        res_fuzz.encoding = 'utf-8'
    
    for line in res_fuzz.iter_lines(decode_unicode=True):
        if (payload in line):
            print("XSS vulnerability via URL parameter discovered")
            print("Vulnerable URL: " + url)
            break
else:
    print("GET NOT OK")
    sys.exit(1)