import scapy.all as scapy
import optparse
import urllib.request
import urllib.error
import urllib.parse
import json
import codecs

def GetOptions():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="The IP Adreess Or An Network Range.")
    options, args = parser.parse_args()
    return options

def ARPScan(ip):
    Hosts = 0
    #AN ARP REQUEST WITH AN DESTENATION TO AN IP
    arp_req = scapy.ARP(pdst=ip)
    #BRODCAST MAC
    brod_mac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #ARP AND BROD TOGETHER IN ONE OBJECT!
    arp_req_brod = brod_mac/arp_req
    answer_list = scapy.srp(arp_req_brod, timeout=1, verbose=False)[0]
    #Gets how many hosts alive!
    for host in answer_list:
        Hosts += 1
    
    clients_list = []
    for element in answer_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list, Hosts

def print_Results(client_list, Hosts):
    print("HOSTS ALIVE: " + str(Hosts))
    print("---" * 25)
    print("IP\t\tMAC\t\tVENDOR")
    print("---" * 25)
    for client in client_list:
        Vendor = CheckVendor(client["mac"])
        print(client["ip"] + "  " + client["mac"] + "  " + str(Vendor))
def CheckVendor(mac):
    url = "https://macvendors.co/api/" + str(mac) + "/json"
    response = urllib.request.urlopen(url)
    obj = json.load(response)
    return obj['result']['company']
    

Options = GetOptions()
if not Options.target:
    scanResult, HostsAlive  = ARPScan("192.168.1.1/24")
else: 
    scanResult, HostsAlive  = ARPScan(Options.target)

print_Results(scanResult, HostsAlive)
