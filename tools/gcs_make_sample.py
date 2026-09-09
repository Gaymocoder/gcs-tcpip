#!/usr/bin/env python3
"""Собирает эталонный pcap для прогона стека: ARP, ICMP и полная сессия TCP."""
import struct, sys

CLIENT_MAC = bytes.fromhex('aabbccddee01')
STACK_MAC  = bytes.fromhex('0a0000000002')
BCAST_MAC  = b'\xff' * 6
CLIENT_IP  = bytes([10, 0, 0, 1])
STACK_IP   = bytes([10, 0, 0, 2])


def checksum(data: bytes, seed: int = 0) -> int:
    total = seed
    if len(data) % 2:
        data += b'\x00'
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    frame = dst + src + struct.pack('!H', ethertype) + payload
    # Ethernet требует минимум 60 байт без FCS
    return frame + b'\x00' * max(0, 60 - len(frame))


def arp_request() -> bytes:
    body = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
    body += CLIENT_MAC + CLIENT_IP + b'\x00' * 6 + STACK_IP
    return eth(BCAST_MAC, CLIENT_MAC, 0x0806, body)


def ipv4(proto: int, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0)
    hdr += CLIENT_IP + STACK_IP
    hdr = hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:]
    return hdr + payload


def icmp_echo(ident: int, seq: int, data: bytes) -> bytes:
    msg = struct.pack('!BBHHH', 8, 0, 0, ident, seq) + data
    msg = msg[:2] + struct.pack('!H', checksum(msg)) + msg[4:]
    return eth(STACK_MAC, CLIENT_MAC, 0x0800, ipv4(1, msg, 0x1000 + seq))


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, data: bytes, ident: int) -> bytes:
    seg = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 4096, 0, 0) + data
    pseudo = CLIENT_IP + STACK_IP + struct.pack('!BBH', 0, 6, len(seg))
    seg = seg[:16] + struct.pack('!H', checksum(pseudo + seg)) + seg[18:]
    return eth(STACK_MAC, CLIENT_MAC, 0x0800, ipv4(6, seg, ident))


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

def main(path: str) -> None:
    payload = b'GCS practice: hello, stack!\n'
    frames = [
        ('ARP: кто такой 10.0.0.2',           arp_request()),
        ('ICMP echo request seq=1',           icmp_echo(0x1234, 1, b'abcdefgh')),
        ('ICMP echo request seq=2',           icmp_echo(0x1234, 2, b'abcdefgh')),
        ('TCP SYN',                           tcp(40001, 8080, 1000, 0, SYN, b'', 0x2001)),
        ('TCP ACK (конец рукопожатия)',       tcp(40001, 8080, 1001, 0x00C0FFEF, ACK, b'', 0x2002)),
        ('TCP PSH+ACK с данными',             tcp(40001, 8080, 1001, 0x00C0FFEF, PSH | ACK, payload, 0x2003)),
        ('TCP FIN+ACK',                       tcp(40001, 8080, 1001 + len(payload), 0x00C0FFEF, FIN | ACK, b'', 0x2004)),
        ('TCP на закрытый порт 9999',         tcp(40002, 9999, 500, 0, SYN, b'', 0x2005)),
    ]
    with open(path, 'wb') as fp:
        fp.write(struct.pack('=IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, (label, frame) in enumerate(frames):
            fp.write(struct.pack('=IIII', 1757000000 + i, 0, len(frame), len(frame)))
            fp.write(frame)
            print(f'  {i + 1}. {label} ({len(frame)} Б)')
    print(f'\nЗаписано {len(frames)} кадров в {path}')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'data/sample.pcap')
