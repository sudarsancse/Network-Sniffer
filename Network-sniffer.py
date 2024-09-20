from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time

# capturing packets
def process_packet(packet):
    global last_packet_time
    if packet.haslayer(IP):
        last_packet_time = time.time() 
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # For TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Segment: {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"Flags: {tcp_layer.flags}")
            print(f"Sequence: {tcp_layer.seq}, Acknowledgment: {tcp_layer.ack}")

        # For UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Segment: {udp_layer.sport} -> {udp_layer.dport}")

        # For ICMP layer
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}")

# Function to check packet sniffing inactivity
def check_inactivity(interval):
    global last_packet_time
    while True:
        current_time = time.time()
        if current_time - last_packet_time > interval:
            print("No packets captured for a while. Please check your network connection.")
            last_packet_time = current_time 
        time.sleep(interval)

if __name__ == "__main__":
    last_packet_time = time.time()
    sniff_interval = 5  # Check conne evey 5 seconds

    print("Starting packet sniffing...")
    
    # Run the inactivity checker in a separate thread
    import threading
    threading.Thread(target=check_inactivity, args=(sniff_interval,), daemon=True).start()

    # Start packet sniffing
    sniff(prn=process_packet, store=False)

