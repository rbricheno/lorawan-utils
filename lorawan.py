import base64
import binascii
import json

# Values from Semtech packet forwarder protocol document:
# https://raw.githubusercontent.com/Lora-net/packet_forwarder/master/PROTOCOL.TXT
identifiers = {
    # Upstream protocol
    0: 'PUSH_DATA',  # Has a JSON payload
    1: 'PUSH_ACK',   # Never has a payload, random token matches that in the PUSH_DATA packet this is acknowledging
    # Downstream protocol
    2: 'PULL_DATA',  # Never has a payload
    3: 'PULL_RESP',  # Has a payload, sent from the (upstream) server, to be emitted by the gateway.
    4: 'PULL_ACK',   # Never has a payload, random token matches that in the PULL_DATA packet this is acknowledging
    5: 'TX_ACK'      # Optionally has a payload containing details of the result of downlink commands
}


class SemtechPacket:
    def __init__(self):
        self.phy_payload = None
        self.protocol_version = None
        self.random_token = None
        self.identifier = None
        self.gateway_id = None
        self.payload = None

    def initialize_from_base64_string(self, data_string: str):
        packet_bytestring = data_string.encode('utf-8')
        self.initialize_from_base64_bytestring(packet_bytestring)

    def initialize_from_base64_bytestring(self, data_bytes: bytes):
        decoded_bytes = base64.decodebytes(data_bytes)
        self.initialize_from_bytes(decoded_bytes)

    def initialize_from_bytes(self, phy_payload: bytes):
        self.phy_payload = phy_payload
        self.protocol_version = phy_payload[0]
        self.random_token = phy_payload[1:3]
        self.identifier = phy_payload[3]
        self.gateway_id = phy_payload[4:12]
        json_payload = phy_payload[12:]
        json_payload_as_string = json_payload.decode('utf-8')
        if json_payload_as_string:
            self.payload = json.loads(json_payload_as_string)
        else:
            self.payload = None

    def gateway_id_as_string(self):
        return binascii.hexlify(bytearray(self.gateway_id)).decode('utf-8')

    def protocol_version_as_string(self):
        return "0x" + format(self.protocol_version, '02x')

    def identifier_as_string(self):
        return "0x" + format(self.identifier, '02x')

    def identifier_as_int(self):
        return int(self.identifier)


# LoRaWAN messages
# From https://lora-alliance.org/resource-hub/lorawantm-specification-v11
message_types = {
    0: 'MTYPE_JOIN_REQUEST',           # Up
    1: 'MTYPE_JOIN_ACCEPT',            # Down
    2: 'MTYPE_UNCONFIRMED_DATA_UP',    # Up
    3: 'MTYPE_UNCONFIRMED_DATA_DOWN',  # Down
    4: 'MTYPE_CONFIRMED_DATA_UP',      # Up
    5: 'MTYPE_CONFIRMED_DATA_DOWN',    # Down
    6: 'MTYPE_REJOIN_REQUEST',
    7: 'MTYPE_PROPRIETARY'
}


class LorawanPacket:
    def __init__(self):
        self.phy_payload = None
        self.mac_header = None
        self.mac_payload = None
        self.message_integrity_code = None
        self.f_ctrl = None
        self.f_opts_len = None
        self.fhdr_len = None
        self.fhdr = None
        self.dev_addr = None

    def initialize_from_base64_string(self, data_string: str):
        packet_bytestring = data_string.encode('utf-8')
        self.initialize_from_base64_bytestring(packet_bytestring)

    def initialize_from_base64_bytestring(self, data_bytes: bytes):
        phy_payload = base64.decodebytes(data_bytes)
        self.initialize_from_bytes(phy_payload)

    def initialize_from_bytes(self, phy_payload: bytes):
        # Sanity check using this packet on https://lorawan-packet-decoder-0ta6puiniaut.runkit.sh/?
        # lorawan_packet.initialize_from_base64_string("QFMeASaAZkYBRXCQ7SU=")
        self.phy_payload = phy_payload
        self.mac_header = phy_payload[0]
        self.mac_payload = phy_payload[1:-4]
        self.message_integrity_code = phy_payload[-4:]
        self.f_ctrl = self.mac_payload[4:6]
        self.f_opts_len = self.f_ctrl[0] & 0xf
        self.fhdr_len = 7 + self.f_opts_len
        self.fhdr = self.mac_payload[0:self.fhdr_len + 1]
        self.dev_addr = self.fhdr[0:4][::-1]  # Reverse this, as it is little-endian in flight

    def mac_header_as_string(self):
        return "0x" + format(self.mac_header, '02x')

    def mic_as_string(self):
        return binascii.hexlify(bytearray(self.message_integrity_code)).decode('utf-8')

    def dev_addr_as_string(self):
        return binascii.hexlify(bytearray(self.dev_addr)).decode('utf-8')
