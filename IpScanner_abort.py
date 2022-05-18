import time
import scapy.all as scapy
from LocalHostInfo import LocalHostInfo

class IpScanner:
    def __init__(self):
        pass

    def get_segment(self, ip):
        ip = str(ip)
        split_ip = ip.split('.')

        # remove last
        split_ip.pop()

        # reconstruct segment
        return ".".join(split_ip)

    def scan(self, ip):
        if self.myos == 'Windows':
            arp_request = scapy.ARP(pdst = ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    # send to all hosts in same network segment

            arp_request_broadcast = broadcast / arp_request

            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

            mac_ip_dict = {}

            for element in answered_list:
                # print(element[1].psrc + "\t\t" + element[1].hwsrc)
                mac_ip_dict[str(element[1].hwsrc)] = str(element[1].psrc)

            return mac_ip_dict  # {MAC:ip}
        elif self.myos == 'Linux':
            # somehow failed in linux
            # https://askubuntu.com/questions/500724/what-is-difference-between-arping-and-arp (diff between arping & arp)
            # https://stackoverflow.com/questions/58259896 (arping in python)
            # https://blog.csdn.net/weixin_52297942/article/details/122606172 (arping can't test self ip)
            resp = scapy.arping(ip)
            print(resp)

    def scan_this_network_segment(self):
        seg = self.get_segment(self.myip)
        seg = seg + '.0/24'
        return self.scan(seg)

    def get_ip_from_MAC(self, dict, MAC):
        if len(dict) == 0:
            return None
            
        # change MAC to lower case
        MAC = str(MAC).lower()

        if MAC in dict:
            return dict[MAC]
        else:
            return None


class LRA_IpScanner(LocalHostInfo, IpScanner):
    def __init__(self):
        LocalHostInfo.get_info(self)

if __name__ == '__main__':

    # start cmd
    # sudo -E python3 GetHostName.py 
    # ref : https://stackoverflow.com/questions/50315645

    def merge_two_dicts(x, y):
        z = x.copy()
        z.update(y)
        return z

    print('\nStart Ip Scanning ...')
    scanner = LRA_IpScanner()

    mac_ip_dict = {}

    # do 5 times
    for try_time in range(5):
        tmp_dict = scanner.scan_this_network_segment()
        mac_ip_dict = merge_two_dicts(mac_ip_dict, tmp_dict)
        print('try : {try_time}, len : {len}'.format(try_time=try_time, len=len(mac_ip_dict)))
        time.sleep(0.1)

    mac_ip_dict = dict(sorted(mac_ip_dict.items(), key=lambda item: item[1]))   # sorted by value


    print("\nIP\t\t\tMAC Address\n-------------------------------------------")

    for key,value in mac_ip_dict.items():
        print('{value}\t\t{key}'.format(key=key, value=value))

    print('\nTotal number of Arp answers : ' + str(len(mac_ip_dict)))
    print('=========================================\n')

    # test for Lab computer 
    # LAB - MAC : BE-0F-9A-E6-EC-C5

    myMAC = 'BC:0F:9A:E6:EC:C5'
    target_ip = scanner.get_ip_from_MAC(mac_ip_dict, myMAC)

    if target_ip is not None:
        print('MAC : ' + myMAC)
        print('Target ip is : ' + target_ip)