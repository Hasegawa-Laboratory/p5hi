from scapy.all import *
import ipaddress
import binascii
import struct
import random

def make_phi_packet(phi_header, paysize=None):
    payload = bytes()    
    
    if phi_header['mode'] != 3:
        phi_header['handshake_phase'] = 0
    if not 'forward_stack' in phi_header:
        phi_header['forward_stack'] = [struct.pack('B' * 24, *[random.randint(0, 255) for i in range(24)]) for j in range(16)]
    
    # mode, phase
    payload += struct.pack('B', (phi_header['mode'] << 6) + (phi_header['handshake_phase'] << 4))
    # plain_dst
    payload += struct.pack('B', int(phi_header['plain_dst'].split('.')[0]))
    payload += struct.pack('B', int(phi_header['plain_dst'].split('.')[1]))
    payload += struct.pack('B', int(phi_header['plain_dst'].split('.')[2]))
    payload += struct.pack('B', int(phi_header['plain_dst'].split('.')[3]))
    # forward_stack
    for item in phi_header['forward_stack']:
        item_bytes = binascii.unhexlify(item)
        payload += item_bytes
            
    if paysize != None:
        payload += binascii.unhexlify('00' * paysize)
            
    pkt = Ether()/IP()/Raw(load=payload)
        
    pkt[Ether].dst = "FF:FF:FF:FF:FF:FF"
    # pkt[Ether].type = 0xFFFF
    pkt[Ether].type = 0x0800
    pkt[IP].src = phi_header['ip_src']
    pkt[IP].dst = phi_header['ip_dst']
    pkt[IP].proto = 200
    return pkt

def parse_phi_packet(pkt):
    phi_header = {}
    phi_header['ip_src'] = pkt[IP].src
    phi_header['ip_dst'] = pkt[IP].dst
    
    payload = bytes(pkt[Raw])
    idx = 0

    # mode, phase
    phi_header['mode'] = payload[idx] >> 6
    phi_header['handshake_phase'] = payload[idx] % (1 << 6) >> 4
    idx += 1
    # plain_dst  
    phi_header['plain_dst'] = str(ipaddress.ip_address(payload[idx:idx + 4]))
    idx += 4
    # forward_stack
    phi_header['forward_stack'] = []
    for i in range(12):
        phi_header['forward_stack'].append(binascii.hexlify(payload[idx:idx + 24]))
        idx += 24
    
    return phi_header

def print_phi_packet(phi_header):
    mode_str = ['forward data', 'backward data', 'VALUE_ERROR', 'handshake']
    handshake_phase_str = ['source -> helper', 'helper -> midway', 'midway -> destination', 'destination -> source']

    print('mode:', phi_header['mode'], ' (%s)' % mode_str[phi_header['mode']])
    if phi_header['mode'] == 3:
        print('handshake_phase:', phi_header['handshake_phase'], ' (%s)' % handshake_phase_str[phi_header['handshake_phase']])
        
    if phi_header['mode'] == 3 and phi_header['handshake_phase'] != 3:
        print('plain_dst:', phi_header['plain_dst'])

    print('forward_stack:')
    for i in range(12):
        print(phi_header['forward_stack'][i])


CONST_0 = 0x736f6d6570736575
CONST_1 = 0x646f72616e646f6d
CONST_2 = 0x6c7967656e657261
CONST_3 = 0x7465646279746573

def rol(x, n):
    y = (x & (2**n) - 1 << (64 - n)) >> (64 - n)
    z = (x & (2**(64-n) - 1)) << n
    return y | z

def sip_round():
    global v0_0, v0_1, v0_2, v0_3, v1_0, v1_1, v1_2, v1_3
    
    v1_0 = (v0_0 + v0_1) % (1 << 64)
    v1_2 = (v0_2 + v0_3) % (1 << 64)
    v1_1 = rol(v0_1, 13)
    v1_3 = rol(v0_3, 16)
    
    v0_1 = v1_1 ^ v1_0
    v0_3 = v1_3 ^ v1_2
    v0_0 = rol(v1_0, 32)
    v0_2 = v1_2
    
    v1_2 = (v0_2 + v0_1) % (1 << 64)
    v1_0 = (v0_0 + v0_3) % (1 << 64)
    v1_1 = rol(v0_1, 17)
    v1_3 = rol(v0_3, 21)
    
    v0_1 = v1_1 ^ v1_2
    v0_3 = v1_3 ^ v1_0
    v0_2 = rol(v1_2, 32)
    v0_0 = v1_0


def sip_hash(key0, key1, messages):
    if not isinstance(messages, list):
        messages = [messages]

    global v0_0, v0_1, v0_2, v0_3, v1_0, v1_1, v1_2, v1_3
    
    v0_0 = CONST_0 ^ key0
    v0_1 = CONST_1 ^ key1
    v0_2 = CONST_2 ^ key0
    v0_3 = CONST_3 ^ key1
    
    for message in messages:
        v0_3 = v0_3 ^ message
        sip_round()
        sip_round()
        v0_0 = v0_0 ^ message
        
    v0_2 = v0_2 ^ 0xFF
    
    sip_round()
    sip_round()
    sip_round()
    sip_round()
    
    return v0_0 ^ v0_1 ^ v0_2 ^ v0_3



def make_fs(prd_mac, prd_addr, suc_addr, enc_keys, auth_keys, nonce=None):
    if nonce == None:
        nonce = random.randint(0, (1 << 64) - 1)

    addr_pair = (int(ipaddress.ip_address(prd_addr)) << 32) | int(ipaddress.ip_address(suc_addr))
    pad = sip_hash(enc_keys[0], enc_keys[1], [nonce])
    ciphertext = pad ^ addr_pair
    mac = sip_hash(auth_keys[0], auth_keys[1], [prd_mac, ciphertext, nonce])

    return (ciphertext << 128) | (nonce << 64) | mac
