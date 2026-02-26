#!/usr/bin/env python3
import ast, re, struct, sys, zlib

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
    return {"proto": pkt[9], "src": ".".join(str(b) for b in pkt[12:16]),
            "dst": ".".join(str(b) for b in pkt[16:20]), "payload": pkt[ihl:total]}


def get_icmp_timestamps(pcap_path):
    ts_list = []
    for ts, raw in parse_pcap(pcap_path):
        ip = parse_ipv4(raw)
        if ip and ip["proto"] == 1 and len(ip["payload"]) >= 8:
            ts_list.append(ts)
    return ts_list


def timing_to_png(pcap_path, threshold=0.1):
    ts = get_icmp_timestamps(pcap_path)
    bits = "".join("0" if ts[i] - ts[i-1] < threshold else "1" for i in range(1, len(ts)))
    for offset in range(8):
        chunk = bits[offset:]
        raw = bytes(int(chunk[i:i+8], 2) for i in range(0, (len(chunk)//8)*8, 8))
        try:
            data = zlib.decompress(raw)
            if data.startswith(PNG_SIG):
                return data, offset
        except Exception:
            continue
    raise ValueError("PNG not found in timing channel.")


def parse_png(png_bytes):
    pos, meta, tail = 8, {}, b""
    while True:
        length = struct.unpack("!I", png_bytes[pos:pos+4])[0]
        c_type = png_bytes[pos+4:pos+8]
        chunk_data = png_bytes[pos+8:pos+8+length]
        if c_type == b"tEXt" and b"\x00" in chunk_data:
            k, v = chunk_data.split(b"\x00", 1)
            meta[k.decode("latin1")] = v.decode("latin1")
        pos += 12 + length
        if c_type == b"IEND":
            tail = png_bytes[pos:]
            break
    return meta, tail


def extract_stage3(tail):
    text = tail[::-1].decode("utf-8")
    encrypted = ast.literal_eval(re.search(r"ENCRYPTED\s*=\s*(b'.*?')", text, re.DOTALL).group(1))
    partial_key = ast.literal_eval(re.search(r"PARTIAL_KEY\s*=\s*(b'.*?')", text, re.DOTALL).group(1))
    return bytes(encrypted), bytes(partial_key)


def xor_decrypt(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def main():
    pcap_path = sys.argv[1]
    png_bytes, bit_offset = timing_to_png(pcap_path)

    if len(sys.argv) >= 3:
        open(sys.argv[2], "wb").write(png_bytes)

    meta, tail = parse_png(png_bytes)
    encrypted, partial_key = extract_stage3(tail)
    full_key = partial_key + bytes.fromhex(meta["Comment"])
    flag = xor_decrypt(encrypted, full_key).decode("utf-8")

    print(f"bit_offset : {bit_offset}")
    print(f"comment    : {meta['Comment']}")
    print(f"flag       : {flag}")


if __name__ == "__main__":
    main()