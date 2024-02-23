import matplotlib.pyplot as plt

def analyze_packets(file_path):
    with open(file_path, "r") as file:
        # Initialize counters for different protocols
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        other_count = 0
        total_packets = 0
    
        # Read each line (packet) from the file
        for line in file:
            # Parse the packet information
            packet_info = line.strip().split()

            # Determine the protocol of the packet
            if "TCP" in packet_info:
                tcp_count += 1
            elif "UDP" in packet_info:
                udp_count += 1
            elif "ICMP" in packet_info:
                icmp_count += 1
            else:
                other_count += 1

            total_packets += 1

    # Display analysis results in a pie chart
    labels = ['TCP', 'UDP', 'ICMP', 'Other']
    sizes = [tcp_count, udp_count, icmp_count, other_count]
    colors = ['lightblue', 'lightgreen', 'orange', 'lightcoral']
    explode = (0.1, 0, 0, 0)  # explode the 1st slice (TCP)

    plt.figure(figsize=(8, 6))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct=lambda p: '{:.0f} ({:.1f}%)'.format(p * total_packets / 100, p), shadow=True, startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title('Packet Analysis')
    plt.show()

# Analyze the packets in the file and display the results in a pie chart
analyze_packets("captured_packets.txt")
