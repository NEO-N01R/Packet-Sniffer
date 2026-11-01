import socket

raw_bytes = socket.inet_aton("192.168.1.50")

for octet in raw_bytes:
    print(f" Decimal = {octet:<3} | Binary Bits = {octet:08b} | Hex_Code = 0x{octet:02x}")

s1_string = "0xc2"

s1_number = int(s1_string, 16) 

s2_string = "0xa8"

s2_number = int(s2_string, 16)

s3_string = "0"

s3_number = int(s3_string, 16)

s4_string = "8"

s4_number = int(s4_string, 16)

print(s1_number, s2_number, s3_number, s4_number)

port_hex_string = "0x01bb"

port_number = int(port_hex_string, 16)

print(f"The packet is targeting Port Number: {port_number}")