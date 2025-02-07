#!/bin/python3

from scapy.all import *
from scapy.layers.inet import IP, TCP
import random
import time
import base64
import json

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

    def create_legitimate_publish(self, peer_state, topic, value):
        """Create MQTT PUBLISH packet with normal sensor data"""
        payload = str(value).encode()
        mqtt_payload = bytes([0x00, len(topic)]) + topic.encode() + payload
        remaining_length = calculate_mqtt_remaining_length(len(mqtt_payload))
        mqtt_data = bytes([MQTTPacket.PUBLISH]) + remaining_length + mqtt_payload
        return self.create_application_packet(peer_state, mqtt_data)

    def create_exfiltration_publish(self, peer_state, topic, legitimate_value, hidden_data):
        """Create MQTT PUBLISH packet with hidden data in an expanded JSON format"""
        # Create a legitimate-looking JSON structure with more detailed metadata
        data = {
            "value": legitimate_value,
            "timestamp": int(time.time()),
            "unit": "C",
            "device_info": {
                "sensor_id": "TEMP001",
                "firmware": "v2.1.5",
                "calibration": "2024-01-15",
                "location": "Room-A",
                "manufacturer": "SensorCorp",
                "model": "TS2000",
                "diagnostic_data": base64.b64encode(hidden_data).decode(),  # Hidden data in diagnostic_data
                "maintenance": {
                    "last_check": "2024-01-20",
                    "next_check": "2024-04-20",
                    "technician": "John Doe",
                    "status": "operational"
                },
                "network": {
                    "protocol": "MQTT",
                    "qos": 0,
                    "retain": False,
                    "broker": "local"
                }
            }
        }
        payload = json.dumps(data).encode()
        
        mqtt_payload = bytes([0x00, len(topic)]) + topic.encode() + payload
        remaining_length = calculate_mqtt_remaining_length(len(mqtt_payload))
        mqtt_data = bytes([MQTTPacket.PUBLISH]) + remaining_length + mqtt_payload
        return self.create_application_packet(peer_state, mqtt_data)

def generate_mixed_pcap(output_file, include_malicious=True):
    # IP addresses (using same as previous code)
    broker = "192.168.1.100"
    temp_sensor = "192.168.1.201"  # Temperature sensor IP (publisher1 from original code)
    mqtt_port = 1883

    # MAC addresses (using same as previous code)
    broker_mac = "02:00:00:00:00:00"
    temp_sensor_mac = "02:00:00:00:00:01"  # Using temperature sensor's MAC from previous code

    packets = []
    timestamp = time.time()

    # Create MQTT object for the temperature sensor
    # Now using same device for both legitimate and malicious traffic
    sensor = MQTTPacket(temp_sensor, broker, 49152, mqtt_port, temp_sensor_mac, broker_mac)
    broker_state = TCPState()

    # TCP handshake
    for pkt in sensor.create_tcp_handshake(broker_state):
        packets.append((timestamp, pkt))
        timestamp += 0.001

    # CONNECT packet
    for pkt in sensor.create_mqtt_connect(broker_state, "temp_sensor"):
        packets.append((timestamp, pkt))
        timestamp += 0.1

    # Generate mixed legitimate and malicious traffic
    sensitive_data = [
        b"BEGIN_CREDENTIAL_DUMP\n" + b"username:admin\npassword:secret123\n" * 1000,
        b"BEGIN_DATABASE_DUMP\n" + b"customer_data:sensitive_info\n" * 1000,
        b"BEGIN_CONFIG_DUMP\n" + b"api_key:12345\nsecret_key:abcde\n" * 1000
    ]

    # Generate 30 publish events
    for i in range(30):
        # Legitimate sensor readings
        temp = round(random.uniform(20.0, 25.0), 1)
        # Format temperature to exactly 7 bytes: "XX.X°C" (where X are digits)
        formatted_temp = f"{temp:04.1f}°C"  # This ensures format like "23.5°C" - exactly 7 bytes
        
        for pkt in sensor.create_legitimate_publish(broker_state, "temperature", formatted_temp):
            packets.append((timestamp, pkt))
            timestamp += random.uniform(1, 2)

        # Mix in malicious packets every few legitimate ones
        if include_malicious and i % 3 == 0 and sensitive_data:
            exfil_data = sensitive_data.pop(0) if sensitive_data else b"Additional sensitive data..."
            temp_malicious = round(random.uniform(20.0, 25.0), 1)
            
            # Send malicious data hidden in legitimate-looking temperature reading
            # Using same topic but with expanded payload
            for pkt in sensor.create_exfiltration_publish(
                broker_state,
                "temperature",  # Same topic as legitimate traffic
                temp_malicious,
                exfil_data
            ):
                packets.append((timestamp, pkt))
                timestamp += random.uniform(1, 2)

    # Write packets to PCAP file
    wrpcap(output_file, [pkt[1] for pkt in packets])

# Generate two PCAP files: one with mixed traffic and one with only legitimate traffic
generate_mixed_pcap("mqtt_mixed_traffic.pcap", include_malicious=True)
