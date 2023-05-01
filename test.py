from scapy.all import *

# type: wifi, eth

# class Adapter:
#   __init__(self, )

print(IFACES)

wifi_keywords = ['wi_fi', 'wifi', 'wi-fi', 'wireless']
eth_keywords = ['ethernet']
virtual_keywords = ['virtual', 'vmware', 'virtualbox']


def contains(mainstr, substr):
    return substr.lower() in mainstr.lower()

# phy: 非模擬


def filter_windows_adapter(type, phy=True):
    adapter = IFACES.data
    di = {}

    if type == 'wifi':
        keyword_candidate = wifi_keywords
    if type == 'eth':
        keyword_candidate = eth_keywords

    for key in IFACES:
        target = adapter[key].description
        going_to_append = False

        # determine state
        for keyword in keyword_candidate:
            if not contains(target, keyword):
                continue

            if phy:
                for virtual_keyword in virtual_keywords:
                    if contains(target, virtual_keyword):
                        break

                    going_to_append = True
            else:
                going_to_append = True

        # append state
        if going_to_append:
            di[key] =  adapter[key]

    return di

if __name__ == '__main__':
  adapters = filter_windows_adapter('wifi', True)
  for key in adapters:
    print(adapters[key].description)
## features
# guid
# description
# index
# mac
# ips[4] or ips[6]
