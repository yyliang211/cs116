#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

counter = 0
#user = ''

def packetcallback(packet):
    global counter
    #print("packet #" + str(counter))
    try:
        #print("in")
        payload = ''
        dec = packet[TCP].load.decode("ascii")
        if Raw in packet:
            payload = packet[TCP].load
        #NULL Scan
        if packet[TCP].flags == 0:
            counter += 1
            print("ALERT #" + str(counter) + ": NULL scan is detected from " + str(packet[IP].src) + " (" + str(packet[TCP].dport) + ")!")
        #Xmas scan
        elif packet[TCP].flags.F & packet[TCP].flags.U & packet[TCP].flags.P:
            counter += 1
            print("ALERT #" + str(counter) + ": Xmas scan is detected from " + str(packet[IP].src) + " (" + str(
                packet[TCP].dport) + "!)")
        #FIN scan
        elif packet[TCP].flags.F:
            counter += 1
            print("ALERT #" + str(counter) + ": FIN scan is detected from " + str(packet[IP].src) + " (" + str(packet[TCP].dport) + ")!")
        #Nikto scan
        elif "Nikto" in dec and packet.haslayer(TCP):
            counter += 1
            print("ALERT #" + str(counter) + ": Nikto scan is detected from " + str(packet[IP].src) + " (" + str(packet[TCP].dport) + ")!")
        #RDP
        if packet[TCP].sport == 3389 and packet.haslayer(TCP):
            counter += 1
            print("ALERT #" + str(counter) + ": Remote Desktop Protocol (RDP) is detected from " + str(packet[IP].src) + " (" + str(packet[TCP].dport) + ")!")
        
        #Username and password in the clear
        if packet.haslayer(TCP):
            #HTTP
            if packet[TCP].dport == 80:
                if 'Authorization: Basic' in dec:
                    for line in dec.splitlines():
                        if 'Authorization: Basic' in line:
                            counter += 1
                            strip = line.strip('Authorization: Basic')
                            b64_line = base64.b64decode(strip)
                            line_str = str(b64_line)
                            line_str = line_str.lstrip("b'")
                            line_str = line_str.rstrip("'")
                            line_str = line_str.split(":")
                            print("ALERT #" + str(counter) + ": Usernames and passwords sent in-the-clear (HTTP) " + "(username:" + line_str[0] + ", password:" + line_str[1] + ")")
            #FTP
            elif packet[TCP].dport == 21:
                global username
                global password
                if "USER" in dec:
                    line = str(dec)
                    username = line.lstrip("USER ")
                if "PASS" in dec:
                    counter += 1
                    line = str(dec)
                    password = line.lstrip("PASS")
                    print("ALERT #" + str(counter) + ": Usernames and passwords sent in-the-clear (FTP) " + "(username:" + username + ", password:" + password + ")")
        #IMAP
        if packet[TCP].dport == 993 or packet[TCP].dport == 143:
            if 'LOGIN' in dec:
                counter += 1
                line = str(dec)
                #username
                line = line.lstrip("3 LOGIN ")
                line = line.split(" ")
                #password
                line[1] = line[1].lstrip('"')
                line[1] = line[1].rstrip('"\r\n')
                print("ALERT #" + str(counter) + ": Usernames and passwords sent in-the-clear (IMAP) " + "(username:" + line[0] + ", password:" + line[1] + ")")
    except:
        pass;

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()

if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")