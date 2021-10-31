import requests
import string
import random
import sys
import getopt

def usage():
    print("Usage: fuzzer.py [URL]")

def main(seclist, base_url):
    #if (len(sys.argv) != 2):
    #    usage()
    #    sys.exit(1)
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hl:u:",["list=","url="])
    except getopt.GetoptError:
        usage()
        sys.exit(1)
    for opt, arg in opts, args:
        if opt == '-h':
            usage()
            sys.exit(1)
        if opt in ("-l", "--list"):
            seclist = arg
        if opt in ("-u", "--url"):
            base_url = arg


def random_lc_fuzz(url):
    letters = string.ascii_lowercase
    fuzz = ''.join(random.choice(letters) for i in range(20))
    return url + "?token=" + fuzz


seclist = ''
base_url = ''
main(seclist, base_url)
print("seclist: " + seclist)
print("base url: " + base_url)
#base_url = sys.argv[1]
url = random_lc_fuzz(base_url)
res_base = requests.get(base_url)
res_fuzz = requests.get(url)
if (res_base.status_code == 200):
    print("GET OK")
    if (res_base.text != res_fuzz.text):
        print("XSS vulnerability via URL parameter discovered")
        print("Vulnerable URL: " + url)
else:
    print("GET NOT OK")
    exit()