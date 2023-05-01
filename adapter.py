from scapy.all import *

from utils import contains, log_ex

# keywords
wifi_keywords = ['wi_fi', 'wifi', 'wi-fi', 'wireless']
eth_keywords = ['ethernet']
virtual_keywords = ['virtual', 'vmware', 'virtualbox']

class Adapter:
  '''
  iface_id's form are related to OS. Acquire from 
  Windows: {uuid}
  '''
  def __init__(self, iface_id): 
    self.id = iface_id
    self.name = "default"
    self.ipv4 = "invalid"
    self.ipv6 = "invalid"
    self.guid = "invalid"
    self.index = -1
    self.mac = "invalid"

    try:
      ins = Adapter.get_instance(self.id)

      self.name = ins.description
      self.ipv4 = ins.ips[4]
      self.ipv6 = ins.ips[6]
      self.guid = ins.guid
      self.index = ins.index
      self.mac = ins.mac

      print("Adapter: {} created", self.name)

    except Exception as e:
      log_ex(e)

  @staticmethod
  def get_instance(id):
    try:
      return IFACES.data[id]
    except:
      raise RuntimeError("Get IFACES failed with id {}", id)

  @staticmethod
  def get_name(id): 
    None

  @staticmethod
  def filter_adapter_bykeyword(type, phy = True):
    adapter = IFACES.data
    ret = {}

    # is string
    if isinstance(type, str):
      if type == "wifi":
        keywords = wifi_keywords
      elif type == "eth" or type == "ethernet":
        keywords = eth_keywords

    # not string, take type as input
    else: 
      keywords = type

    # processing 