from lorawan import SemtechPacket, LorawanPacket

# Print out some information about packets logged by github.com/rbricheno/loralogger
with open('lora.log', 'r') as file:
    for line in file:
        parts = line.split(',')
        timestamp_from_file = parts[0]

        # This can be discarded, we will get the same value again in the same way from the udp packet.
        # gateway_id_from_file = parts[1].strip()

        semtech_packet = SemtechPacket()
        semtech_packet.initialize_from_base64_string(parts[2].strip())

        if semtech_packet.identifier_as_int() == 0:

            if 'rxpk' in semtech_packet.payload:
                print("Timestamp: " + timestamp_from_file)
                print("Protocol version: " + semtech_packet.protocol_version_as_string())
                print("Gateway ID: " + semtech_packet.gateway_id_as_string())
                if len(semtech_packet.payload['rxpk']) > 1:
                    raise ValueError("Bad packet, multiple rxpk")
                print(semtech_packet.payload['rxpk'][0])

                lorawan_packet = LorawanPacket()
                lorawan_packet.initialize_from_base64_string(semtech_packet.payload['rxpk'][0]['data'])

                print("MHdr: " + lorawan_packet.mac_header_as_string())
                print("MIC: " + lorawan_packet.mic_as_string())
                print("DevAddr: " + lorawan_packet.dev_addr_as_string())
                print()
