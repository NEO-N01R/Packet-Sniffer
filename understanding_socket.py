import socket
import struct
import os
from datetime import datetime

def log_traffic(log_entry):
    with open("network_traffic.log", "a") as log_file:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_file.write(f"NeoPackets_[{timestamp}] {log_entry}\n")
        
def start_sniffer():

    if os.name == 'posix':
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        print("[+] Linux detected. Packet-level Layer 2 pipeline opened successfully.")
        payload_offset = 14  
        
    else:
    
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        
        print("[+] Windows detected. Configuring Promiscuous Mode")
        local_ip = socket.gethostbyname(socket.gethostname())
        sniffer.bind((local_ip, 0))
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        payload_offset = 0   

    print("[+] Sniffer running normally. Monitoring all live interface traffic...\n")

    try:
        while True:
            raw_packets, address = sniffer.recvfrom(65535)

            if os.name == 'posix':
                if len(raw_packets) < 14:
                    continue
                eth_protocol = struct.unpack('!H', raw_packets[12:14])[0]
            else:
                eth_protocol = 0x0800

            if eth_protocol == 0x0800 and len(raw_packets) >= (payload_offset + 20):
                ip_header = raw_packets[payload_offset:payload_offset + 20]
                ihl = (ip_header[0] & 0x0F) * 4
                protocol_type, src_ip, dest_ip = ip_header[9], socket.inet_ntoa(ip_header[12:16]), socket.inet_ntoa(ip_header[16:20])
                transport_offset = payload_offset + ihl
            elif eth_protocol == 0x86DD and len(raw_packets) >= (payload_offset + 40):
                ip6_header = raw_packets[payload_offset:payload_offset + 40]
                protocol_type = ip6_header[6]
                src_ip, dest_ip = socket.inet_ntop(socket.AF_INET6, ip6_header[8:24]), socket.inet_ntop(socket.AF_INET6, ip6_header[24:40])
                transport_offset = payload_offset + 40
            else:
                continue
            
            routing_info = f"IP Routing: {src_ip} -> {dest_ip} | Protocol ID: {protocol_type}"
            print(routing_info); log_traffic(routing_info)

            if len(raw_packets) < (transport_offset + 4): continue
            
            if protocol_type in (6, 17):
                p_name = "TCP" if protocol_type == 6 else "UDP"
                print(f"   [Protocol: {p_name}] -> Slicing for {p_name} Ports")
                s_port, d_port = struct.unpack('!HH', raw_packets[transport_offset:transport_offset + 4])
                info = f"   {p_name} Ports: {s_port} -> {d_port}"
            elif protocol_type in (1, 58):
                label = "ICMPv6" if eth_protocol == 0x86DD else "ICMP"
                print(f"   [Protocol: {label}] -> Slicing for {label} Type and Code")
                i_type, i_code = struct.unpack('!BB', raw_packets[transport_offset:transport_offset + 2])
                info = f"   {label} Type: {i_type} | {label} Code: {i_code}"
            else:
                info = f"   [Protocol: {protocol_type}] -> No specific slicing implemented."

            print(info); log_traffic(info)

            

    except KeyboardInterrupt:
        print("\n[+] Sniffer stopped by user.")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    start_sniffer()
