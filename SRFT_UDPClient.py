#!/usr/bin/env python3
##sudo python3 SRFT_UDPClient.py 172.31.23.62 test1.txt

import socket
import struct
import sys
import os
import time


# Configuration
CLIENT_IP   = "172.31.24.43"
CLIENT_PORT = 8888
SERVER_PORT = 9999
OUTPUT_DIR  = "./received_files"
RECV_TIMEOUT = 5.0          # seconds to wait for next packet before giving up

# Request retransmission config
REQ_TIMEOUT     = 3.0       # seconds to wait for first data after sending request
REQ_MAX_RETRIES = 3         # how many times to re-send the file request

# Application Header
HEADER_FORMAT = '!IIBH'
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # = 11 bytes

# Flags
FLAG_DATA = 0x01   # Data packet
FLAG_ACK  = 0x02   # Acknowledgement packet
FLAG_EOF  = 0x04   # End of file
FLAG_REQ  = 0x08   # File request from client


def compute_checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def verify_checksum(data: bytes, expected: int) -> bool:
    return compute_checksum(data) == expected

def build_header(seq_num: int, ack_num: int, flags: int, checksum: int) -> bytes:
    return struct.pack(HEADER_FORMAT, seq_num, ack_num, flags, checksum)

def parse_header(data: bytes):
    if len(data) < HEADER_SIZE:
        return None
    seq_num, ack_num, flags, checksum = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:]
    return seq_num, ack_num, flags, checksum, payload

def build_ip_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    version_ihl    = (4 << 4) | 5
    dscp_ecn       = 0
    total_length   = 20 + 8 + payload_len
    identification = 0
    flags_offset   = 0
    ttl            = 64
    protocol       = socket.IPPROTO_UDP
    chk            = 0
    src            = socket.inet_aton(src_ip)
    dst            = socket.inet_aton(dst_ip)
    return struct.pack("!BBHHHBBH4s4s",
                       version_ihl, dscp_ecn, total_length,
                       identification, flags_offset,
                       ttl, protocol, chk,
                       src, dst)

def build_udp_header(src_port: int, dst_port: int, payload: bytes,
                     src_ip: str, dst_ip: str) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0)

def build_packet(src_ip: str, src_port: int,
                 dst_ip: str, dst_port: int,
                 payload: bytes) -> bytes:
    udp_hdr = build_udp_header(src_port, dst_port, payload, src_ip, dst_ip)
    ip_hdr  = build_ip_header(src_ip, dst_ip, len(payload))
    return ip_hdr + udp_hdr + payload

def parse_packet(raw: bytes, expected_dst_port: int):
    if len(raw) < 28:
        return None
    ip_header = raw[:20]
    ihl      = (ip_header[0] & 0x0F) * 4
    protocol = ip_header[9]
    if protocol != socket.IPPROTO_UDP:
        return None
    udp_header = raw[ihl:ihl + 8]
    if len(udp_header) < 8:
        return None
    src_port, dst_port, length, _ = struct.unpack("!HHHH", udp_header)
    if dst_port != expected_dst_port:
        return None
    payload = raw[ihl + 8: ihl + length]
    return payload


def send_ack(sock, server_ip: str, ack_seq: int):
    """Send an ACK for a specific sequence number."""
    ack_header = build_header(seq_num=0, ack_num=ack_seq, flags=FLAG_ACK, checksum=0)
    pkt = build_packet(CLIENT_IP, CLIENT_PORT, server_ip, SERVER_PORT, ack_header)
    sock.sendto(pkt, (server_ip, 0))


def print_progress_bar(received: int, total: int, bar_len: int = 40,
                       start_time: float = None):
    """
    Print a progress bar that overwrites itself on the same line.
    If total is unknown (0), show packet count with a spinner.
    """
    if total > 0:
        pct    = min(received / total, 1.0)
        filled = int(bar_len * pct)
        bar    = '█' * filled + '░' * (bar_len - filled)
        speed_str = ""
        if start_time is not None:
            elapsed = time.time() - start_time
            if elapsed > 0:
                pps = received / elapsed
                speed_str = f" | {pps:.0f} pkt/s"
        print(f"\r[Client] [{bar}] {pct*100:5.1f}%  "
              f"({received}/{total} pkts){speed_str}   ", end='', flush=True)
    else:
        # Total unknown: show spinner + count
        spinner = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
        s = spinner[received % len(spinner)]
        print(f"\r[Client] {s} {received} packets received...   ",
              end='', flush=True)


def send_request(sock, server_ip: str, filename: str):
    """Build and send a file request packet (FLAG_REQ)."""
    request    = filename.encode()
    chk        = compute_checksum(request)
    req_header = build_header(seq_num=0, ack_num=0, flags=FLAG_REQ, checksum=chk)
    pkt        = build_packet(CLIENT_IP, CLIENT_PORT, server_ip, SERVER_PORT,
                              req_header + request)
    sock.sendto(pkt, (server_ip, 0))


def wait_for_first_response(sock, timeout: float):
    """Wait for any valid packet from the server. Returns raw bytes or None."""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            raw_data, _ = sock.recvfrom(65535)
            payload = parse_packet(raw_data, CLIENT_PORT)
            if payload is not None:
                return raw_data
        except socket.timeout:
            return None


# Client main
def run_client(server_ip: str, filename: str):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, os.path.basename(filename))

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # ── Send file request with retransmission ──
    first_raw = None
    for attempt in range(1, REQ_MAX_RETRIES + 1):
        send_request(sock, server_ip, filename)
        if attempt == 1:
            print(f"[Client] Requested file '{filename}' from {server_ip}:{SERVER_PORT}")
        else:
            print(f"[Client] Re-sending request (attempt {attempt}/{REQ_MAX_RETRIES})...")
        first_raw = wait_for_first_response(sock, REQ_TIMEOUT)
        if first_raw is not None:
            break
    else:
        print(f"[Client] Server not responding after {REQ_MAX_RETRIES} attempts. Aborting.")
        sock.close()
        return

    # ── Receive file data ──
    # In Selective Repeat, the server sends multiple packets at once.
    # The client's job is simple:
    #   - Receive each DATA packet
    #   - Send back an ACK for that specific seq (even if out of order)
    #   - Buffer all received chunks in a dict keyed by seq
    #   - At the end, sort by seq and reassemble the file
    # This is identical to what we already do — the dict acts as the
    # receive buffer, and per-packet ACKs are exactly what SR needs.

    received_chunks  = {}
    packets_received = 0
    acks_sent        = 0
    duplicates       = 0
    checksum_errors  = 0
    total_packets    = 0   # learned from EOF seq_num; 0 = unknown
    start_time       = time.time()

    sock.settimeout(RECV_TIMEOUT)
    print(f"[Client] Receiving (Selective Repeat mode)...")

    pending_raw = first_raw

    while True:
        try:
            if pending_raw is not None:
                raw_data = pending_raw
                pending_raw = None
            else:
                raw_data, _ = sock.recvfrom(65535)

            payload = parse_packet(raw_data, CLIENT_PORT)
            if payload is None:
                continue

            parsed = parse_header(payload)
            if parsed is None:
                continue

            seq_num, ack_num, flags, checksum, data = parsed

            # ── Handle EOF ──
            if flags == FLAG_EOF:
                if data.startswith(b"ERROR:"):
                    print(f"\r[Client] Server error: {data.decode()}          ")
                    sock.close()
                    return

                total_packets = seq_num  # EOF seq = total data packets
                send_ack(sock, server_ip, seq_num)
                acks_sent += 1

                # Final progress bar at 100%
                print_progress_bar(packets_received, total_packets, start_time=start_time)
                print(f"\n[Client] Received EOF, sent ACK.")
                break

            # ── Handle DATA packet ──
            if flags == FLAG_DATA:
                if not verify_checksum(data, checksum):
                    checksum_errors += 1
                    continue

                if seq_num not in received_chunks:
                    received_chunks[seq_num] = data
                    packets_received += 1

                    # Update progress bar every 1000 packets
                    if packets_received % 1000 == 0:
                        estimated_total = total_packets if total_packets > 0 else 0
                        print_progress_bar(packets_received, estimated_total,
                                           start_time=start_time)
                else:
                    duplicates += 1

                send_ack(sock, server_ip, seq_num)
                acks_sent += 1

        except socket.timeout:
            print(f"\n[Client] Timeout — no data for {RECV_TIMEOUT}s. "
                  f"Assuming transfer complete.")
            break

    elapsed = time.time() - start_time

    # ── Write output file ──
    if received_chunks:
        ordered_keys = sorted(received_chunks.keys())

        # Check for gaps (missing packets)
        expected = list(range(ordered_keys[0], ordered_keys[-1] + 1))
        missing  = set(expected) - set(ordered_keys)
        if missing:
            print(f"[Client] WARNING: {len(missing)} missing packets: "
                  f"{sorted(missing)[:10]}{'...' if len(missing) > 10 else ''}")

        file_bytes = b"".join(received_chunks[k] for k in ordered_keys)

        with open(output_path, "wb") as f:
            f.write(file_bytes)

        print(f"\n[Client] File saved to      : {output_path}")
        print(f"[Client] Packets received    : {packets_received}")
        print(f"[Client] Duplicate packets   : {duplicates}")
        print(f"[Client] ACKs sent           : {acks_sent}")
        print(f"[Client] Checksum errors     : {checksum_errors}")
        print(f"[Client] Total bytes         : {len(file_bytes)}")
        print(f"[Client] Transfer time       : {elapsed:.2f}s")
    else:
        print("[Client] No data received.")

    sock.close()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Raw sockets require root. Run with: sudo python3 SRFT_UDPClient.py <server_ip> <filename>")
        sys.exit(1)

    if len(sys.argv) != 3:
        print("Usage: sudo python3 SRFT_UDPClient.py <server_ip> <filename>")
        sys.exit(1)

    SERVER_IP_ARG = sys.argv[1]
    FILENAME_ARG  = sys.argv[2]

    run_client(SERVER_IP_ARG, FILENAME_ARG)
