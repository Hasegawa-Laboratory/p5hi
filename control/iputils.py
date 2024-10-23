import ipaddress
import random

class IPLPM:
    def __init__(self):
        self.root = {0: None}

    def __insert_rec(self, node, ip_int, prefix_len, value):
        if prefix_len == 0:
            node[0] = value
            while len(node) < 3:
                node[len(node)] = {0: value}
            return
        while len(node) < 3:
            node[len(node)] = {0: None}
        b = 1 if ip_int >= (1 << 31) else 0
        ip_int = ip_int * 2 % (1 << 32)
        self.__insert_rec(node[1 + b], ip_int, prefix_len - 1, value)

    def __setitem__(self, key, value):
        (ip_prefix, prefix_len) = key
        ip_int = int(ipaddress.ip_address(ip_prefix))
        self.__insert_rec(self.root, ip_int, prefix_len, value)

    def __get_rec(self, node, ip_int, prefix_len):
        if len(node) == 1:
            return node[0]
        elif prefix_len == -1:
            return None
        b = 1 if ip_int >= (1 << 31) else 0
        ip_int = ip_int * 2 % (1 << 32)
        return self.__get_rec(node[1 + b], ip_int, prefix_len - 1)
        
    def __getitem__(self, ip_addr):
        ip_int = int(ipaddress.ip_address(ip_addr))
        res = self.__get_rec(self.root, ip_int, 32)
        return res


def get_rand_ip(prefixes):
    prefix = random.choice(prefixes)
    netaddr = int(prefix[0])
    netmask = int(prefix[1])

    subnet = random.randint(0, (1 << 32) - 1)
    subnet = subnet & ~netmask
    rand_ip = ipaddress.IPv4Address(netaddr | subnet)
    
    return rand_ip
