# This file (pcap_parser.py) was written and implemented by Mohamed Habak.
# ChatGPT was used as a learning aid to help design the structure of detection functions,
# provide debugging guidance, and improve explanatory comments throughout the code.
# All final implementation logic, testing, and validation were done by me.


import pyshark                      # For reading and parsing PCAP files
from collections import Counter     # For counting occurrences (protocols, IPs)
from datetime import datetime       # For converting timestamps
import ipaddress                    # For validating and checking private/external IPs
import asyncio                      # Required by pyshark internally for asynchronous operations


# HL7 markers and configuration
MEDICAL_PATTERNS = ["MSH|", "PID|", "OBR|", "ORC|"]         # HL7 identifiers to look for in packet payloads

# Load trusted IPs from file, or use default if file is missing
try:
    with open("known_servers.txt", "r") as file:
        KNOWN_SERVERS = set(line.strip() for line in file if line.strip())
except FileNotFoundError:
    print("known_servers.txt file not found.")
    KNOWN_SERVERS = {"192.168.1.10", "192.168.1.20"} 

# Threshold for detecting sudden spikes in HL7 messages (messages per minute)
TRAFFIC_SPIKE_THRESHOLD = 50                    

# ---------------- HELPER FUNCTIONS ---------------- #

def extract_payload(pkt):
    """
    Safely extract packet payload as a string.
    """

    # Attempt to read TCP or UDP payload and convert from hex to text
    try:
        if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"): # i am doing this to check if this packet has a tcp layer and if that tcp layer has a payload attribute and then reading the payload attribute instead of trying to read everything in the packet at once using something like pkt.get_raw_packet() 
            payload = bytes.fromhex(pkt.tcp.payload.replace(":", "")).decode(errors="ignore")
            # first pkt.tcp.payload gets the TCP layer's payload in hex format (e.g. "48:65:6C:6C:6F")  
            # then .replace(":", "") removes colons to get a clean hex string ("48656C6C6F")  
            # then bytes.fromhex(...) converts the hex string into raw bytes (b"Hello")
            # finally .decode(errors="ignore") decodes the bytes into a readable text string ("Hello"), ignoring bad bytes

            # so id i did something like this: payload = bytes(pkt.get_raw_packet()).decode(errors="ignore") this could cause the program to fail because the raw packet includes all headers and other non-payload data that might not decode cleanly. by specifically targeting the tcp payload, i get just the data portion that is more likely to be valid text.
            return payload
        elif hasattr(pkt, "udp") and hasattr(pkt.udp, "payload"):
            payload = bytes.fromhex(pkt.udp.payload.replace(":", "")).decode(errors="ignore")
            return payload
        else:
            return ""
    except Exception:
        return ""

def is_external_ip(ip):
    """
    Determine if an IP is external (not private/local).
    """

    # Check if the given IP address is private using ipaddress library
    try:
        answer = ipaddress.ip_address(ip)
        if answer.is_private:   
            return False
        else:
            return True
    except ValueError:
        return False

# ---------------- ATTACK DETECTION FUNCTIONS ---------------- #

def detect_replay_attack(packets):
    """
    Detect repeated HL7 messages (replay attacks).
    """
    # Track messages that have already been seen
    seen = set()
    alerts = []

    # Loop through packets and extract payloads
    for i, packet in packets:
        pkt = extract_payload(packet)

        # Check for HL7 patterns and generate alerts if duplicates are found
        for pat in MEDICAL_PATTERNS:
            if pat in pkt:
                if pkt in seen:
                    alerts.append({
                        "type": "replay-attack",
                        "description": f"Repeated HL7 message detected from {packet.ip.src}",
                        "packet_id": i
                    })
                else:
                    seen.add(pkt)
                break
    return alerts

def detect_data_exfiltration(packets):
    """
    Detect HL7 data sent to unknown or external destinations.
    """
    alerts = []

    # Examine each packet for HL7 markers and unknown/external destinations
    for i, packet in packets:
        pkt = extract_payload(packet)
        for pat in MEDICAL_PATTERNS:
            if pat in pkt:
                try:
                    dst_ip = packet.ip.dst
                except AttributeError:
                    continue
                
                if is_external_ip(dst_ip) and dst_ip not in KNOWN_SERVERS:
                    alerts.append({
                        "type": "data-exfiltration",
                        "description": f"HL7 traffic sent to external IP {dst_ip}",
                        "packet_id": i
                    })
                break
    return alerts

def detect_unencrypted_hl7(packets):
    """
    Detect HL7 messages sent over non-encrypted channels.
    """
    alerts = []
    
    # Check each packet for HL7 markers and unencrypted transmission
    for i, packet in packets:
        pkt = extract_payload(packet)
        for pat in MEDICAL_PATTERNS:
            if pat in pkt:
                tcp_layer = getattr(packet, "tcp", None) #instead of using dst_port = packet.tcp.dstport for example. i used getattr to avoid AttributeError. for example if the packet is not TCP, it won't have a tcp attribute and it could give an error
                udp_layer = getattr(packet, "udp", None) #while tcp is the one mostly used for HL7, i should still check for udp just in case

                dst_port = None
                if tcp_layer:
                    dst_port = getattr(tcp_layer, "dstport", None)
                elif udp_layer:
                    dst_port = getattr(udp_layer, "dstport", None)

                port = "TCP" if tcp_layer else "UDP" if udp_layer else "Unknown"

                if (tcp_layer and not hasattr(packet, "ssl")) or udp_layer: # i added "or udp_layer" because UDP is generally not encrypted
                    alerts.append({
                        "type": "unencrypted-hl7",
                        "description": f"unencrypted HL7 message found over {port} port {dst_port}",
                        "packet_id": i
                    })
                    break
    return alerts

def detect_traffic_spike(packets):
    """
    Detect sudden spikes in HL7 traffic volume.
    """
    
    # Group packets into minute-based buckets and count HL7 messages
    buckets = {}
    alerts = []
    for i, packet in packets:
        pkt = extract_payload(packet)
        for pat in MEDICAL_PATTERNS:
            if pat in pkt:
                try: # because sometimes malformed packets might not have this attribute
                    timestamp = float(packet.sniff_timestamp) # this will give me the time the packet was captured in seconds since January 1st, 1970.
                except AttributeError:
                    continue

                minute_bucket = int(timestamp // 60) # i want to group the packets by minute, so I divide the timestamp by 60 and take the integer part so that all packets in the same minute fall into the same bucket
                buckets[minute_bucket] = buckets.get(minute_bucket, 0) + 1 #this "buckets.get(minute_bucket, 0)" means that if the minute_bucket is already in the buckets dictionary, it will return its current count. If it's not there yet, it will return 0. Then, i added 1 to that value to account for the current packet. which will give us a dictionary where the keys are the minute buckets and the values are the counts of HL7 messages in those minutes

    # Generate alerts if message count exceeds threshold
    for minute, count in buckets.items():
        if count > TRAFFIC_SPIKE_THRESHOLD:
            alerts.append({
                "type": "traffic-spike",
                "description": f"High HL7 traffic volume detected: {count} messages in one minute starting at {datetime.fromtimestamp(minute * 60)}",
                "time_bucket": minute
            })
    return alerts


# ---------------- MAIN PARSER ---------------- #

def parse_pcap(filepath, max_packets=10000):
    """
    Parse a PCAP file, extract traffic data, and detect HL7-related anomalies.
    """
    try:                            # the reason why i added this part was because pyshark internally uses asyncio for some operations (meaning, it can multitask and do things concurrently). but to use asyncio (to multitask), an event loop is needed to manage how and when tasks are run. so, if there's no event loop already running in the current thread, pyshark might throw an error. by adding this code, i ensure that there's always an event loop available for pyshark to use, preventing potential runtime errors related to missing event loops.
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # Open the PCAP file using pyshark.FileCapture
    try:
        cap = pyshark.FileCapture(filepath, keep_packets=False)
    except Exception as e:
        print(f"Error opening pcap file: {e}")
        return None

    # Initialize containers for analysis
    protocol_counts = Counter()
    top_talkers = Counter()
    packets = []
    raw_packets = []
    alerts = []

    # Loop through packets up to max_packets
    for i, pkt in enumerate(cap):
        if i >= max_packets:
            break

        # Extract source/destination IPs
        ip_layer = getattr(pkt, "ip", None)   # getattr(., ., None) handles cases if the packet doesn't have an IP layer
        if ip_layer:
            src_ip = getattr(ip_layer, "src", None)
            dst_ip = getattr(ip_layer, "dst", None)
        else:
            src_ip = None
            dst_ip = None

        # Extract protocol, timestamp, and payload
        proto = pkt.transport_layer # transport_layer can be TCP, UDP, etc.
        timestamp = datetime.fromtimestamp(float(pkt.sniff_timestamp))
        payload = extract_payload(pkt)

        # Extract ports if available
        if proto:
            dst_port = int(getattr(pkt[proto], "dstport", 0))
            src_port = int(getattr(pkt[proto], "srcport", 0))
        else:
            dst_port = 0
            src_port = 0

        # Store packet data for summary and detection
        raw_packets.append(pkt)  # store the raw packet for detection functions
        packets.append({         # store the lightweight info for summary
            "id": i,
            "number": pkt.number,
            "src": src_ip,
            "dst": dst_ip,
            "protocol": proto,
            "timestamp": timestamp,
            "payload": payload,
            "dst_port": dst_port,
            "src_port": src_port
        })

        # Update protocol and top talker statistics
        if proto:
            protocol_counts[proto] += 1
        if src_ip:
            top_talkers[src_ip] += 1
        if dst_ip:
            top_talkers[dst_ip] += 1

            
    # Close capture file
    cap.close()
    
    # Run detection functions on the captured packets
    indexed_packets = list(enumerate(raw_packets))  # pairs each packet with its index to make it easier to identify them later
    alerts.extend(detect_replay_attack(indexed_packets))    # Similiar to append just meant for appending multiple elements not just a single one
    alerts.extend(detect_data_exfiltration(indexed_packets))     
    alerts.extend(detect_unencrypted_hl7(indexed_packets))
    alerts.extend(detect_traffic_spike(indexed_packets))

    # Prepare and return summary dictionary
    summary = {
        "packet_count": len(packets),
        "protocol_counts": dict(protocol_counts), # dict() is a counter method used to convert the Counter object to a regular dictionary for easier readability like changing Counter({'TCP': 150, 'UDP': 50}) to {'TCP': 150, 'UDP': 50}
        "top_talkers": top_talkers.most_common(10), # most_common(10) is a counter method that returns a list of the n most common elements and their counts from the most common to the least. in this case, it will give me the top 10 IPs that appeared most frequently in the traffic along with how many times they appeared
        "alerts": alerts,
        "packets": packets
    }

    return summary