import requests
import string
import random
import sys
import argparse

def usage():
    print("Usage: fuzzer.py -u [URL] optional: -w [wordlist file]")

def fuzz(url, file_line):
    payload = file_line
    base_url = url
    fuzz_url = url + "?token=" + payload
    res_base = requests.get(base_url)
    res_fuzz = requests.get(fuzz_url)
    if (res_base.status_code == 200):
        print("GET OK")
        if payload in res_fuzz.text:
            print("XSS vulnerability via URL parameter discovered")
            print("Vulnerable URL: " + fuzz_url)
    else:
        print("GET NOT OK")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(prog='XSS Fuzzer', description='Fuzzer for Reflected XSS bugs, with option for wordlist')
    parser.add_argument('-w', '--wordlist', type=str, help='location of a wordlist file to be used')
    parser.add_argument('url', type=str, help="target url for reflected XSS attack")
    args = parser.parse_args()
    url = args.url
    if (args.wordlist):
        file = open(args.wordlist, 'r')
        for file_line in file.readlines():
            fuzz(url, file_line)
    else:
        file = open('xss.txt', 'r')
        for file_line in file.readlines():
            fuzz(url, file_line)

main()