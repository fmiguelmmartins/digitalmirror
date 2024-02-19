from scapy.all import sendp
from scapy.layers.l2 import Ether
import socket


def send_wol_layer3(mac_address, port):
    """
    This functions sends a wol to a target host using sockets (layer 3)
    """

    # Clean this mac_address and tokenize it convert from Hex to Byte
    mac_clean = mac_address.replace(":", "").replace("-", "")
    mac_byte = bytes.fromhex(mac_clean)

    # Create payload 0xFF * 6 bytes + Mac address * 16
    payload = b"\xFF" * 6 + mac_byte * 16

    # Create the socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Set permissions
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Send the magic packet
        sock.sendto(payload, ("<broadcast>", port))


def send_wol_layer2(mac_address):
    """
    This functions sends a wol to a target host (layer 2)
    """

    # Clean this mac_address and tokenize it convert from Hex to Byte
    mac_clean = mac_address.replace(":", "").replace("-", "")
    mac_byte = bytes.fromhex(mac_clean)

    # Create payload x0FF * 6 bytes + Mac address * 16
    payload = b"\xFF" * 6 + mac_byte * 16

    # Create the ethernet frame, send to broadcast address and bind the payload to it
    magic_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / payload

    # Send packet
    sendp(magic_packet, "Ethernet")


if __name__ == "__main__":
    send_wol_layer3("58:b4:82:a1:f3:38", 9)
