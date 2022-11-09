'''
    PYTHON-NETWORK-SCANNER
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

    https://stackoverflow.com/questions/15335753/nmap-not-found-class-nmap-nmap-portscannererror

'''

'''
    You need to install:
    1. pip install getmac
    2. pip install matplotlib
    3. pip install prettytable
    4. install nmap from: https://nmap.org/download#windows
    5. install npcap from: https://npcap.com/#:~:text=Downloading%20and%20Installing%20Npcap%20Free%20Edition
    
    # if you can't find any devices in your local network, try to 
    1. open cmd
    2. run nmap -T4 -sn 192.168.0.1/24
    3. if you see can't open eth0/ eth1. Make sure you have npcap installed!
    ref: https://github.com/nmap/npcap/issues/335
'''

# import region
from getmac import get_mac_address
from matplotlib.font_manager import json_load
from prettytable import PrettyTable

from datetime import date
from device import Device
from network import Network

import json
import os
import sys

def create_device_list(devices, data):
    ''' Return a dictonary like {'known': [], 'unknown': []}

    Creates 2 lists from devices (class Device) and makes them available in a dictionary
       - 'known': list of known devices (mac address included in the data/device.json)
       - 'unknown': list of unknown devices (not included)
    '''
    known_devices = []
    unknown_devices = []

    for host, info in devices:
        device = Device(info['mac'], host, info['hostnames'][0]['name'], data)
        if device.name:
            known_devices.append(device)
        else:
            unknown_devices.append(device)

    return {'known': known_devices, 'unknown': unknown_devices}

def create_mac_ip_dict(devices):
    mac_ip_dict = {}
    for host, info in devices:
        mac_ip_dict[info['mac']] = host
    return mac_ip_dict

def get_MAC_from_json(path, category, network, mac_ip_map):
    MAC_array = json_load(path)
    MAC_devices = MAC_array[category]

    # turn into MAC list
    target_MACs = [device['MAC'] for device in MAC_devices]
    target_IPs = network.findIP_of_MACs(target_MACs, mac_ip_map)

    return target_IPs, target_MACs

def args_check(args):

    flags = {}

    if len(args) == 1:
        return flags

    # args --enableall
    labels = ['--enableall']
    if any(label in args for label in labels):
        enable_all = True
        flags['func_all'] = True
    else:
        enable_all = False

    # args --verbose
    labels = ['--verbose', '-v']
    if enable_all or any(label in args for label in labels):
        flags['func_verbose'] = True

    # args --log
    labels = ['--log', '-l']
    if  enable_all or any(label in args for label in labels):
        flags['func_verbose'] = True
        flags['func_log'] = True

    return flags
    
if __name__ == '__main__':

    flags = args_check(sys.argv)

    # device.json
    dataPath = 'data'
    try:
        with open("{}/devices.json".format(dataPath), "r") as readFile:
                json_devices = json.load(readFile)
    except FileNotFoundError:
                json_devices = {}

#                 print('''No valid "data/devices.json" found. Please create one with the following format:
# {
#     "00:00:00:00:00:00":
#     {
#       "type": "Device",
#       "owner": "John Appleseed",
#       "location": null,
#       "allowed": true
#     }
# }
#             ''')

    # Main
    network = Network(input('Input IP segment you want to search, default is your current IP: \n'))

    try:
        devices = network.get_devices()
    except KeyboardInterrupt:
        print('You stopped scanning. Scanning may take a while. If it takes too long, there may be a problem with the connection. Did you specify the correct network?')
        sys.exit()

    for host, info in devices:
        info['mac'] = get_mac_address(ip=host)

    if 'func_verbose' in flags:
        data = create_device_list(devices, json_devices)
        log_text = ''

        table = PrettyTable()
        table.field_names = ["MAC ADDRESS", "IP", "NAME IN NETWORK", "NAME", 'LOCATION', 'ALLOWED']
        for device in data['known']:
            table.add_row(device.to_list())
            log_text += '{}\n'.format(device.to_string())
        
        print('Known Devices\n{}'.format(table))

        table = PrettyTable()
        table.field_names = ["MAC ADDRESS", "IP", "NAME IN NETWORK"]
        for device in data['unknown']:
            table.add_row(device.to_list()[:3])
            log_text += '{}\n'.format(device.to_string())
        
        print('Unknown Devices\n{}'.format(table))

        print('Total : {} devices'.format(len(data['known'])+len(data['unknown'])))

        if not os.path.isdir(dataPath):
            os.mkdir(dataPath)

        if 'func_log' in flags:
            with open("{}/{}.log".format(dataPath, date.today()), "a") as appendFile:
                appendFile.write(log_text)
                print('You can find a log file with all devices in "data/{}.log"'.format(date.today()))


    mac_ip_map = create_mac_ip_dict(devices)
    
    # read from MAC.json
    MAC_json_path =  dataPath + '/RasPI_MAC.json'
    target_IPs, target_MACs = get_MAC_from_json(MAC_json_path, 'devices', network, mac_ip_map)

    table = PrettyTable()
    table.field_names = ["TARGET MAC", "IP"]
    for idx in range(len(target_IPs)):
        table.add_row([target_MACs[idx], target_IPs[idx]])
    
    print('\n\nTarget IP\n{}'.format(table))

    ########################################################################################################

    # we can get target ip so prepare to
    # import webbrowser
    # for ip in target_IPs:
    #     search_success = (ip != None)
    #     if search_success:
    #         default_port = 8000
    #         webbrowser.open('http://' + str(ip) + ':' + str(default_port) + '/request_ip')
