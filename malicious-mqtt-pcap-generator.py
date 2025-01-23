#!/bin/python3

from scapy.all import *
from scapy.layers.inet import IP, TCP
import random
import time
import base64

def calculate_mqtt_remaining_length(payload_length):
    remaining_bytes = []
    length = payload_length
    while True:
        byte = length % 128
        length = length // 128
        if length > 0:
            byte |= 0x80
        remaining_bytes.append(byte)
        if length == 0:
            break
    return bytes(remaining_bytes)

class TCPState:
    def __init__(self):
        self.seq = random.randint(1000, 9000)
        self.ack = random.randint(1000, 9000)

class MQTTPacket:
    CONNECT = 0x10
    CONNACK = 0x20
    PUBLISH = 0x30
    SUBSCRIBE = 0x82
    SUBACK = 0x90

    def __init__(self, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.tcp_state = TCPState()
        
    def create_tcp_handshake(self, peer_state):
        syn = Ether(src=self.src_mac, dst=self.dst_mac) / \
              IP(src=self.src_ip, dst=self.dst_ip) / \
              TCP(sport=self.src_port, dport=self.dst_port, flags='S', 
                  seq=self.tcp_state.seq)
        
        syn_ack = Ether(src=self.dst_mac, dst=self.src_mac) / \
                  IP(src=self.dst_ip, dst=self.src_ip) / \
                  TCP(sport=self.dst_port, dport=self.src_port, flags='SA',
                      seq=peer_state.seq, ack=self.tcp_state.seq + 1)
        
        ack = Ether(src=self.src_mac, dst=self.dst_mac) / \
              IP(src=self.src_ip, dst=self.dst_ip) / \
              TCP(sport=self.src_port, dport=self.dst_port, flags='A',
                  seq=self.tcp_state.seq + 1, ack=peer_state.seq + 1)
        
        self.tcp_state.seq += 1
        peer_state.seq += 1
        self.tcp_state.ack = peer_state.seq
        peer_state.ack = self.tcp_state.seq
        
        return [syn, syn_ack, ack]

    def create_application_packet(self, peer_state, mqtt_data):
        tcp_packet = Ether(src=self.src_mac, dst=self.dst_mac) / \
                    IP(src=self.src_ip, dst=self.dst_ip) / \
                    TCP(sport=self.src_port, dport=self.dst_port, flags='PA',
                        seq=self.tcp_state.seq, ack=self.tcp_state.ack) / \
                    Raw(mqtt_data)
        
        ack_packet = Ether(src=self.dst_mac, dst=self.src_mac) / \
                    IP(src=self.dst_ip, dst=self.src_ip) / \
                    TCP(sport=self.dst_port, dport=self.src_port, flags='A',
                        seq=peer_state.seq, ack=self.tcp_state.seq + len(mqtt_data))
        
        self.tcp_state.seq += len(mqtt_data)
        peer_state.ack = self.tcp_state.seq
        
        return [tcp_packet, ack_packet]

    def create_mqtt_connect(self, peer_state, client_id):
        variable_header = b'\x00\x04MQTT\x04'
        connect_flags = 0x02
        keep_alive = b'\x00\x3c'
        variable_header += bytes([connect_flags]) + keep_alive
        payload = bytes([0x00, len(client_id)]) + client_id.encode()
        remaining_length = calculate_mqtt_remaining_length(len(variable_header) + len(payload))
        mqtt_data = bytes([MQTTPacket.CONNECT]) + remaining_length + variable_header + payload
        return self.create_application_packet(peer_state, mqtt_data)

    def create_malicious_publish(self, peer_state, topic, payload):
        """Create MQTT PUBLISH packet with potentially malicious content"""
        mqtt_payload = bytes([0x00, len(topic)]) + topic.encode() + payload
        remaining_length = calculate_mqtt_remaining_length(len(mqtt_payload))
        mqtt_data = bytes([MQTTPacket.PUBLISH]) + remaining_length + mqtt_payload
        return self.create_application_packet(peer_state, mqtt_data)

def generate_exfiltration_pcap(output_file):
    # IP addresses
    broker = "192.168.1.100"
    attacker = "192.168.1.250"  # Suspicious client
    mqtt_port = 1883

    # MAC addresses (using locally administered addresses)
    broker_mac = "02:00:00:00:00:00"
    attacker_mac = "02:00:00:00:00:FF"  # Using FF to distinguish attacker

    packets = []
    timestamp = time.time()

    # Create MQTT objects with MAC addresses
    malicious_client = MQTTPacket(attacker, broker, 49160, mqtt_port, attacker_mac, broker_mac)
    broker_state = TCPState()

    # TCP handshake
    for pkt in malicious_client.create_tcp_handshake(broker_state):
        packets.append((timestamp, pkt))
        timestamp += 0.001

    # CONNECT packet with innocent-looking client ID
    for pkt in malicious_client.create_mqtt_connect(broker_state, "sensor_device"):
        packets.append((timestamp, pkt))
        timestamp += 0.1

    # 1. Data exfiltration through topic names
    sensitive_data = [
        "username=admin;password=secret123",
        base64.b64encode(b"credit_card=4532016243780456").decode(),
        base64.b64encode(b"ssn=123-45-6789").decode(),
    ]

    for data in sensitive_data:
        malicious_topic = f"data/sensor/{data}"
        for pkt in malicious_client.create_malicious_publish(broker_state, malicious_topic, b"normal_reading"):
            packets.append((timestamp, pkt))
            timestamp += 5.0

    # 2. Large payload exfiltration
    # Create a large payload (simulated sensitive data)
    large_payload = b"BEGIN_DUMP\n"
    large_payload += b"SECRET_DATA\n" * 50000  # About 600KB of repeated text
    large_payload += b"END_DUMP"

    # Split into smaller chunks to avoid TCP fragmentation
    chunk_size = 1024
    chunks = [large_payload[i:i + chunk_size] for i in range(0, len(large_payload), chunk_size)]

    for i, chunk in enumerate(chunks):
        for pkt in malicious_client.create_malicious_publish(broker_state, f"sensor/readings/part{i}", chunk):
            packets.append((timestamp, pkt))
            timestamp += 0.1

    wrpcap(output_file, [pkt[1] for pkt in packets])

# Generate the malicious PCAP file
generate_exfiltration_pcap("mqtt_exfiltration.pcap")
