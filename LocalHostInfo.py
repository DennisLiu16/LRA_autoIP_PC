import socket
import platform

class LocalHostInfo:
    def __init__(self):
        pass
    
    def get_info(self):
        print('myip : ' + self.get_ip())
        print('OS : ' + self.get_os())

    def get_os(self):
        self.myos = platform.system()
        return self.myos

    def get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()

        self.myip = IP
        return IP