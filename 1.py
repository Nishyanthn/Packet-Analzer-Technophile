from scapy.all import *

def print_smtp_auth_to_data_payloads(pcap_file):
    packets = rdpcap(pcap_file)
    found_auth = False
    auth_payload = ""

    for packet in packets:
        if packet.haslayer(TCP) and packet[TCP].dport == 25:
            # Check if the packet is SMTP traffic (destination port 25)
            payload = packet[TCP].payload
            if isinstance(payload, Raw):a
                # Check if the payload is Raw (contains actual data)
                payload_data = payload.load.decode('utf-8', errors='ignore')
                
                if found_auth:
                    if "DATA" in payload_data:
                        # If "DATA" command is found, break the loop
                        break
                    else:
                        # Otherwise, append payload data
                        auth_payload += payload_data

                if "AUTH LOGIN" in payload_data:
                    # If "AUTH LOGIN" command is found, start collecting payload data
                    found_auth = True
                    auth_payload += payload_data

    print(auth_payload)

print_smtp_auth_to_data_payloads(file_path)
