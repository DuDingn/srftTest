#!/usr/bin/env python3
##sudo python3 SRFT_UDPServer.py

import socket
import struct
import os
import sys
import time
import threading


# Configuration
SERVER_IP   = "0.0.0.0"   # Listen on all interfaces
SERVER_ACTUAL_IP = "172.31.23.62"  # Server's private IP
SERVER_PORT = 9999
CHUNK_SIZE  = 1400         # bytes per data chunk (safe under typical MTU)
FILES_DIR   = "./server_files"  # Directory where served files live

# Sliding Window Configuration
WINDOW_SIZE    = 8         # number of packets that can be in-flight at once
ACK_TIMEOUT    = 2.0       # seconds before retransmitting an individual packet
MAX_RETRIES    = 5         # max retransmissions per packet before giving up

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
    version_ihl   = (4 << 4) | 5
    dscp_ecn      = 0
    total_length  = 20 + 8 + payload_len
    identification = 0
    flags_offset  = 0
    ttl           = 64
    protocol      = socket.IPPROTO_UDP
    chk           = 0
    src           = socket.inet_aton(src_ip)
    dst           = socket.inet_aton(dst_ip)
    return struct.pack("!BBHHHBBH4s4s",
                       version_ihl, dscp_ecn, total_length,
                       identification, flags_offset,
                       ttl, protocol, chk,
                       src, dst)

def build_udp_header(src_port: int, dst_port: int, payload: bytes, src_ip: str, dst_ip: str) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0)

def build_packet(src_ip: str, src_port: int,
                 dst_ip: str, dst_port: int,
                 payload: bytes) -> bytes:
    udp_hdr = build_udp_header(src_port, dst_port, payload, src_ip, dst_ip)
    ip_hdr  = build_ip_header(src_ip, dst_ip, len(payload))
    return ip_hdr + udp_hdr + payload

def parse_packet(raw: bytes):
    if len(raw) < 28:
        return None
    ip_header = raw[:20]
    ihl = (ip_header[0] & 0x0F) * 4
    protocol = ip_header[9]
    src_ip = socket.inet_ntoa(ip_header[12:16])
    if protocol != socket.IPPROTO_UDP:
        return None
    udp_header = raw[ihl:ihl + 8]
    if len(udp_header) < 8:
        return None
    src_port, dst_port, length, _ = struct.unpack("!HHHH", udp_header)
    if dst_port != SERVER_PORT:
        return None
    payload = raw[ihl + 8: ihl + length]
    return src_ip, src_port, dst_port, payload

def send_data_packet(sock, src_ip, src_port, dst_ip, dst_port, seq_num, chunk):
    chk     = compute_checksum(chunk)
    header  = build_header(seq_num, ack_num=0, flags=FLAG_DATA, checksum=chk)
    payload = header + chunk
    pkt     = build_packet(src_ip, src_port, dst_ip, dst_port, payload)
    sock.sendto(pkt, (dst_ip, 0))


def send_file_selective_repeat(sock, filepath, client_ip, client_port):
    """
    Send a file using Selective Repeat with a sliding window.

    Window state:
      - send_base: the oldest unACKed sequence number (left edge of window)
      - next_seq:  the next sequence number to send (right edge of what we've sent)
      - Window range: [send_base, send_base + WINDOW_SIZE)

    For each packet in the window we track:
      - acked[seq]:      has this seq been ACKed?
      - send_time[seq]:  when was it last sent? (for per-packet timeout)
      - retries[seq]:    how many times has it been retransmitted?
      - chunks[seq]:     the data chunk for this seq

    Flow:
      1. Fill the window: send packets until next_seq reaches send_base + WINDOW_SIZE
         or we run out of file data.
      2. Listen for ACKs with a short poll timeout.
      3. When an ACK arrives, mark that seq as acked.
         If send_base is acked, slide the window forward past all consecutive acked seqs.
      4. Check for per-packet timeouts: if any unACKed packet in the window has been
         waiting longer than ACK_TIMEOUT, retransmit just that packet (Selective Repeat).
      5. Repeat until all packets are ACKed.
    """
    file_size = os.path.getsize(filepath)

    # Pre-read all chunks into memory (simpler for window management)
    all_chunks = []
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            all_chunks.append(chunk)

    total_packets = len(all_chunks)
    if total_packets == 0:
        return True, 0, 0, 0

    # Window state
    send_base = 0                # left edge: oldest unACKed seq
    next_seq  = 0                # next seq to send for the first time
    acked     = {}               # seq → True if ACKed
    send_time = {}               # seq → timestamp of last send
    retries   = {}               # seq → retransmit count

    total_sent          = 0
    total_retransmits   = 0

    POLL_TIMEOUT = 0.05  # 50ms poll interval for recvfrom

    print(f"[Server] Sending {total_packets} packets (window={WINDOW_SIZE}, "
          f"timeout={ACK_TIMEOUT}s, max_retries={MAX_RETRIES})")

    while send_base < total_packets:
        # ── Step 1: Fill window with new packets ──
        while (next_seq < total_packets and
               next_seq < send_base + WINDOW_SIZE):
            send_data_packet(sock, SERVER_ACTUAL_IP, SERVER_PORT,
                             client_ip, client_port,
                             next_seq, all_chunks[next_seq])
            send_time[next_seq] = time.time()
            retries[next_seq]   = 0
            acked[next_seq]     = False
            total_sent += 1
            next_seq += 1

        # ── Step 2: Listen for ACKs (short poll) ──
        sock.settimeout(POLL_TIMEOUT)
        try:
            raw_data, _ = sock.recvfrom(65535)
            parsed = parse_packet(raw_data)
            if parsed is not None:
                src_ip, src_port, _, payload = parsed
                if src_ip == client_ip and src_port == client_port:
                    parsed_hdr = parse_header(payload)
                    if parsed_hdr is not None:
                        _, ack_num, flags, _, _ = parsed_hdr
                        if flags == FLAG_ACK:
                            # Mark this seq as ACKed
                            if send_base <= ack_num < next_seq:
                                if not acked.get(ack_num, False):
                                    acked[ack_num] = True

                            # Slide window: advance send_base past consecutive ACKs
                            while send_base < total_packets and acked.get(send_base, False):
                                # Clean up state for packets that left the window
                                del acked[send_base]
                                del send_time[send_base]
                                del retries[send_base]
                                send_base += 1

        except socket.timeout:
            pass  # no ACK this poll cycle, that's fine

        # ── Step 3: Check per-packet timeouts, retransmit as needed ──
        now = time.time()
        for seq in range(send_base, next_seq):
            if acked.get(seq, False):
                continue  # already ACKed, skip

            if now - send_time[seq] >= ACK_TIMEOUT:
                # This packet timed out
                if retries[seq] >= MAX_RETRIES:
                    print(f"[Server] seq={seq} failed after {MAX_RETRIES} retries. Aborting.")
                    return False, total_sent, total_retransmits, total_packets

                retries[seq] += 1
                total_retransmits += 1
                print(f"[Server] Timeout seq={seq}, retransmit "
                      f"(attempt {retries[seq]}/{MAX_RETRIES})")
                send_data_packet(sock, SERVER_ACTUAL_IP, SERVER_PORT,
                                 client_ip, client_port,
                                 seq, all_chunks[seq])
                send_time[seq] = time.time()
                total_sent += 1

        # Print progress periodically
        if send_base > 0 and send_base % 200 == 0:
            print(f"[Server]   ... {send_base}/{total_packets} acknowledged")

    return True, total_sent, total_retransmits, total_packets


# Server main loop
def run_server():
    os.makedirs(FILES_DIR, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.bind((SERVER_IP, 0))

    print(f"[Server] Listening on port {SERVER_PORT} (raw socket)...")
    print(f"[Server] Serving files from: {os.path.abspath(FILES_DIR)}")
    print(f"[Server] Mode: Selective Repeat | Window: {WINDOW_SIZE} | "
          f"Timeout: {ACK_TIMEOUT}s | Max retries: {MAX_RETRIES}")

    sock.settimeout(None)

    while True:
        try:
            raw_data, addr = sock.recvfrom(65535)
            parsed = parse_packet(raw_data)
            if parsed is None:
                continue

            client_ip, client_port, _, payload = parsed
            parsed_hdr = parse_header(payload)
            if parsed_hdr is None:
                continue
            seq_num, ack_num, flags, checksum, data = parsed_hdr

            if flags != FLAG_REQ:
                continue

            filename = data.decode(errors="replace").strip()
            print(f"\n[Server] Request from {client_ip}:{client_port} → file: '{filename}'")

            filepath = os.path.join(FILES_DIR, filename)
            if not os.path.isfile(filepath):
                err_msg = f"ERROR: File '{filename}' not found.".encode()
                chk     = compute_checksum(err_msg)
                header  = build_header(0, 0, FLAG_EOF, chk)
                pkt     = build_packet(SERVER_ACTUAL_IP, SERVER_PORT,
                                       client_ip, client_port, header + err_msg)
                sock.sendto(pkt, (client_ip, 0))
                print(f"[Server] File not found.")
                continue

            # ── Send file with Selective Repeat ──
            start_time = time.time()
            file_size  = os.path.getsize(filepath)

            ok, total_sent, total_retransmits, total_packets = \
                send_file_selective_repeat(sock, filepath, client_ip, client_port)

            if ok:
                # Send EOF with retransmission
                eof_seq    = total_packets  # EOF seq = one past last data seq
                eof_header = build_header(eof_seq, ack_num=0, flags=FLAG_EOF, checksum=0)
                eof_pkt    = build_packet(SERVER_ACTUAL_IP, SERVER_PORT,
                                          client_ip, client_port, eof_header)
                for attempt in range(MAX_RETRIES):
                    sock.sendto(eof_pkt, (client_ip, 0))
                    sock.settimeout(ACK_TIMEOUT)
                    try:
                        while True:
                            raw, _ = sock.recvfrom(65535)
                            p = parse_packet(raw)
                            if p is None:
                                continue
                            si, sp, _, pl = p
                            if si != client_ip or sp != client_port:
                                continue
                            ph = parse_header(pl)
                            if ph is None:
                                continue
                            _, an, fl, _, _ = ph
                            if fl == FLAG_ACK and an == eof_seq:
                                print(f"[Server] EOF acknowledged by client.")
                                raise StopIteration  # break out of both loops
                    except socket.timeout:
                        continue
                    except StopIteration:
                        break
                else:
                    print(f"[Server] EOF sent but no ACK (client may have finished).")
            else:
                print(f"[Server] Transfer FAILED.")

            elapsed = time.time() - start_time
            print(f"[Server] '{filename}' ({file_size} bytes): "
                  f"{total_sent} sends, {total_retransmits} retransmits, {elapsed:.2f}s")

            sock.settimeout(None)

        except KeyboardInterrupt:
            print("\n[Server] Shutting down.")
            break
        except Exception as e:
            print(f"[Server] Error: {e}")
            import traceback
            traceback.print_exc()
            sock.settimeout(None)

    sock.close()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Raw sockets require root. Run with: sudo python3 SRFT_UDPServer.py")
        sys.exit(1)
    run_server()
