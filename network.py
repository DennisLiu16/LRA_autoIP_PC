'''
    python-network-scanner
    Copyright (C) 2021  devmarcstorm

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    https://www.cnblogs.com/nicole-zhang/p/14763214.html
    
'''

# import region
import traceback
from nmap import PortScanner
from LocalHostInfo import LocalHostInfo

class Network(LocalHostInfo):
    def __init__(self, ip_seg=None):
        try:
            LocalHostInfo.get_info(self)
            if ip_seg == None or ip_seg == '':
                # default - scan host ip segment 
                self.target_ip_seg = self.myip
            else:
                # parse ip_seg
                # clear all '/' in ip_seg
                self.target_ip_seg = ip_seg.split('/')[0]

                # make sure not a segment
                if len(self.target_ip_seg.split('.')) == 3:
                    self.target_ip_seg += '.0'

        except Exception:
            print('NetWork init error\n')
            print(traceback.format_exc())
        
    def get_devices(self):
        '''Return a list

        Creates a list of items that contain device information
        '''
        network_to_scan = self.target_ip_seg+'/24'

        p_scanner = PortScanner()
        print('\nScanning {}...'.format(network_to_scan))
        p_scanner.scan(hosts=network_to_scan, arguments='-sn -sP -PE -PA21,23,80,3389 -T 5')   # you should tune here 
        device_list = [(device, p_scanner[device]) for device in p_scanner.all_hosts()]

        # should sort here

        print('Scanning Over\n')
        return device_list
    
    def findIP_of_MACs(self, target_MACs, MAC_IP_map):
        if target_MACs == None:
            return None
        
        # change to upper
        try:
            target_MACs = [MAC.lower() for MAC in target_MACs]
        except:
            print('\nChange MAC to upper failed\n')
            return None

        # IPs_list = [MAC_IP_map[MAC] for MAC in target_MACs] -- cause key error

        IPs_list = []

        for MAC in target_MACs:
            if MAC in MAC_IP_map:
                IPs_list.append(MAC_IP_map[MAC])
            else:
                IPs_list.append(None)

        return IPs_list
