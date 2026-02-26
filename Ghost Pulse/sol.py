#!/usr/bin/env python3
import struct, sys, zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def parse_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        e = "<" if gh[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        *_, link_type = struct.unpack(e + "IHHIIII", gh)
        while True:
            ph = f.read(16)
            if not ph: break
            ts_sec, ts_usec, incl_len, _ = struct.unpack(e + "IIII", ph)
            data = f.read(incl_len)
            if link_type == 228:
                raw = data
            elif link_type == 1:
                if len(data) < 14 or struct.unpack("!H", data[12:14])[0] != 0x0800: continue
                raw = data[14:]
            yield ts_sec + ts_usec / 1e6, raw


def parse_ipv4(pkt):
    if len(pkt) < 20: return None
    ihl = (pkt[0] & 0x0F) * 4
    total = min(struct.unpack("!H", pkt[2:4])[0], len(pkt))
    return {"proto": pkt[9], "payload": pkt[ihl:total]}


def get_icmp_timestamps(pcap_path):
    ts_list = []
    for ts, raw in parse_pcap(pcap_path):
        ip = parse_ipv4(raw)
        if ip and ip["proto"] == 1 and len(ip["payload"]) >= 8:
            ts_list.append(ts)
    return ts_list


def extract_png(pcap_path, out_path, threshold=0.1):
    ts = get_icmp_timestamps(pcap_path)
    bits = "".join("0" if ts[i] - ts[i-1] < threshold else "1" for i in range(1, len(ts)))

    for offset in range(8):
        chunk = bits[offset:]
        raw = bytes(int(chunk[i:i+8], 2) for i in range(0, (len(chunk)//8)*8, 8))
        try:
            data = zlib.decompress(raw)
            if data.startswith(PNG_SIG):
                with open(out_path, "wb") as f:
                    f.write(data)
                print(f"[+] PNG extrait ({len(data)} bytes) → {out_path}  [bit_offset={offset}]")
                return
        except Exception:
            continue

    print("[!] PNG non trouvé dans le canal temporel.")


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "ghost_pulse.pcap"
    out  = sys.argv[2] if len(sys.argv) > 2 else "hidden.png"
    extract_png(pcap, out)