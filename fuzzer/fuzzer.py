import requests
import string
import random
import sys
import getopt

def usage():
    print("Usage: fuzzer.py [URL]")

def random_lc_fuzz(url):
    letters = string.ascii_lowercase
    fuzz = ''.join(random.choice(letters) for i in range(20))
    return url + "?token=" + fuzz


if (len(sys.argv) != 2):
        usage()
        sys.exit(1)
base_url = sys.argv[1]
url = random_lc_fuzz(base_url)
res_base = requests.get(base_url)
res_fuzz = requests.get(url)
if (res_base.status_code == 200):
    print("GET OK")
    if (res_base.text != res_fuzz.text):
        print("XSS vulnerability via URL parameter discovered")
        print("Vulnerable URL: " + url)
    else:
        print("No XSS vulnerability found (yet)")
else:
    print("GET NOT OK")
    exit()