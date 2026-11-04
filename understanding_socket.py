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
            
            if len(raw_packets) < (payload_offset + 20):
                continue
                
            ip_header_bytes = raw_packets[payload_offset : payload_offset + 20]
            
            protocol_type = ip_header_bytes[9]
            
            src_ip_raw = ip_header_bytes[12:16]
            dest_ip_raw = ip_header_bytes[16:20]
            
            src_ip = socket.inet_ntoa(src_ip_raw)
            dest_ip = socket.inet_ntoa(dest_ip_raw)
            
            routing_info = f"IP Routing: {src_ip} -> {dest_ip} | Protocol ID: {protocol_type}"
            print(routing_info)
            log_traffic(routing_info)

            if protocol_type == 6:
                print("   [Protocol: TCP] -> Slicing for TCP Ports")
                tcp_ports_bytes = raw_packets[payload_offset + 20 : payload_offset + 24]
                src_port, dest_port = struct.unpack('!HH', tcp_ports_bytes)

                port_info = f"   TCP Ports: {src_port} -> {dest_port}"
                print(port_info)
                log_traffic(port_info)

            elif protocol_type == 17:
                print("   [Protocol: UDP] -> Slicing for UDP Ports")
                udp_ports_bytes = raw_packets[payload_offset + 20 : payload_offset + 24]
                src_port, dest_port = struct.unpack('!HH', udp_ports_bytes)

                port_info = f"   UDP Ports: {src_port} -> {dest_port}"
                print(port_info)
                log_traffic(port_info)

            elif protocol_type == 1:
                print("   [Protocol: ICMP] -> Slicing for ICMP Type and Code")
                icmp_bytes = raw_packets[payload_offset + 20 : payload_offset + 22]
                icmp_type, icmp_code = struct.unpack('!BB', icmp_bytes)

                port_info = f"   ICMP Type: {icmp_type} | ICMP Code: {icmp_code}"
                print(port_info)
                log_traffic(port_info)

            else:
                print(f"   [Protocol: {protocol_type}] -> No specific slicing implemented.")

    except KeyboardInterrupt:
        print("\n[+] Sniffer stopped by user.")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    start_sniffer()
