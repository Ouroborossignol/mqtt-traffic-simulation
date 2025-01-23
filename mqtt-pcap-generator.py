#!/bin/python3

from scapy.all import *
from scapy.layers.inet import IP, TCP
import random
import time

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
        """Create TCP handshake packets with synchronized sequence numbers"""
        # Add Ethernet layer with MAC addresses to all packets
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

    # Rest of the MQTTPacket class methods remain unchanged...
    def create_mqtt_connect(self, peer_state, client_id):
        variable_header = b'\x00\x04MQTT\x04'
        connect_flags = 0x02
        keep_alive = b'\x00\x3c'
        variable_header += bytes([connect_flags]) + keep_alive
        payload = bytes([0x00, len(client_id)]) + client_id.encode()
        remaining_length = calculate_mqtt_remaining_length(len(variable_header) + len(payload))
        mqtt_data = bytes([MQTTPacket.CONNECT]) + remaining_length + variable_header + payload
        return self.create_application_packet(peer_state, mqtt_data)

    def create_mqtt_publish(self, peer_state, topic, payload):
        mqtt_payload = bytes([0x00, len(topic)]) + topic.encode() + payload.encode()
        remaining_length = calculate_mqtt_remaining_length(len(mqtt_payload))
        mqtt_data = bytes([MQTTPacket.PUBLISH]) + remaining_length + mqtt_payload
        return self.create_application_packet(peer_state, mqtt_data)

    def create_mqtt_subscribe(self, peer_state, packet_id, topic, qos=0):
        variable_header = packet_id.to_bytes(2, byteorder='big')
        payload = bytes([0x00, len(topic)]) + topic.encode() + bytes([qos])
        remaining_length = calculate_mqtt_remaining_length(len(variable_header) + len(payload))
        mqtt_data = bytes([MQTTPacket.SUBSCRIBE]) + remaining_length + variable_header + payload
        return self.create_application_packet(peer_state, mqtt_data)

    def create_mqtt_suback(self, peer_state, packet_id, return_code=0x00):
        variable_header = packet_id.to_bytes(2, byteorder='big')
        payload = bytes([return_code])
        remaining_length = calculate_mqtt_remaining_length(len(variable_header) + len(payload))
        mqtt_data = bytes([MQTTPacket.SUBACK]) + remaining_length + variable_header + payload
        return self.create_application_packet(peer_state, mqtt_data)

def generate_mqtt_pcap(output_file):
    # IP addresses
    broker = "192.168.1.100"
    publisher1 = "192.168.1.201"
    publisher2 = "192.168.1.202"
    subscriber1 = "192.168.1.203"
    subscriber2 = "192.168.1.204"
    mqtt_port = 1883

    # MAC addresses (using locally administered addresses)
    broker_mac = "02:00:00:00:00:00"
    pub1_mac = "02:00:00:00:00:01"
    pub2_mac = "02:00:00:00:00:02"
    sub1_mac = "02:00:00:00:00:03"
    sub2_mac = "02:00:00:00:00:04"

    packets = []
    timestamp = time.time()

    # Create MQTT objects with MAC addresses
    pub1 = MQTTPacket(publisher1, broker, 49152, mqtt_port, pub1_mac, broker_mac)
    pub2 = MQTTPacket(publisher2, broker, 49153, mqtt_port, pub2_mac, broker_mac)
    sub1 = MQTTPacket(subscriber1, broker, 49154, mqtt_port, sub1_mac, broker_mac)
    sub2 = MQTTPacket(subscriber2, broker, 49155, mqtt_port, sub2_mac, broker_mac)
    
    broker_states = {
        'pub1': TCPState(),
        'pub2': TCPState(),
        'sub1': TCPState(),
        'sub2': TCPState()
    }

    # TCP handshakes
    for client, broker_state in [
        (pub1, broker_states['pub1']),
        (pub2, broker_states['pub2']),
        (sub1, broker_states['sub1']),
        (sub2, broker_states['sub2'])
    ]:
        for pkt in client.create_tcp_handshake(broker_state):
            packets.append((timestamp, pkt))
            timestamp += 0.001

    # CONNECT packets
    for client, state, name in [
        (pub1, broker_states['pub1'], "temp_sensor"),
        (pub2, broker_states['pub2'], "humidity_sensor"),
        (sub1, broker_states['sub1'], "temp_monitor"),
        (sub2, broker_states['sub2'], "humidity_monitor")
    ]:
        for pkt in client.create_mqtt_connect(state, name):
            packets.append((timestamp, pkt))
            timestamp += 0.1

    # SUBSCRIBE packets with SUBACK responses
    for sub, state, topic, broker_mac in [
        (sub1, broker_states['sub1'], "temperature", broker_mac),
        (sub2, broker_states['sub2'], "humidity", broker_mac)
    ]:
        # Subscribe packet and its ACK
        for pkt in sub.create_mqtt_subscribe(state, 1, topic):
            packets.append((timestamp, pkt))
            timestamp += 0.1
        
        # Create broker response with SUBACK
        broker_resp = MQTTPacket(broker, sub.src_ip, mqtt_port, sub.src_port, broker_mac, sub.src_mac)
        broker_resp.tcp_state = state
        for pkt in broker_resp.create_mqtt_suback(sub.tcp_state, 1):
            packets.append((timestamp, pkt))
            timestamp += 0.1

    # Generate publish events
    for i in range(10):
        # Temperature updates
        temp = f"23.5°C"  # Exactly 7 bytes
        for pkt in pub1.create_mqtt_publish(broker_states['pub1'], "temperature", temp):
            packets.append((timestamp, pkt))
            timestamp += 0.1

        # Humidity updates
        humidity = f"{random.uniform(40.0, 60.0):.1f}%"
        for pkt in pub2.create_mqtt_publish(broker_states['pub2'], "humidity", humidity):
            packets.append((timestamp, pkt))
            timestamp += random.uniform(0.5, 1.5)

    wrpcap(output_file, [pkt[1] for pkt in packets])

# Generate the PCAP file
generate_mqtt_pcap("mqtt_sensor_traffic.pcap")
