import re
from collections import defaultdict, Counter
# candump -l 格式常见形态：
# (1700000000.123456) vcan0 123#1122334455667788
PAT = re.compile(r"\((?P<ts>[\d\.]+)\)\s+(?P<if>\S+)\s+(?P<id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)")

def parse_log(path: str):
    frames = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = PAT.search(line)
            if not m:
                continue
            ts = float(m.group("ts"))
            can_id = int(m.group("id"), 16)
            data_hex = m.group("data")
            data = bytes.fromhex(data_hex) if data_hex else b""
            frames.append((ts, can_id, data))
    return frames

def id_frequency(frames):
    # 粗略统计：每个 ID 每秒帧数（基于首末时间）
    by_id = defaultdict(list)
    for ts, can_id, data in frames:
        by_id[can_id].append(ts)

    freq = {}
    for can_id, tss in by_id.items():
        if len(tss) < 2:
            freq[can_id] = 0.0
            continue
        duration = max(tss) - min(tss)
        freq[can_id] = (len(tss) - 1) / duration if duration > 0 else 0.0
    return freq

def changing_bytes(frames, target_id):
    # 找某个 ID 的哪些字节发生变化
    payloads = [data for _, can_id, data in frames if can_id == target_id]
    if len(payloads) < 2:
        return []

    max_len = max(len(p) for p in payloads)
    changed = [False] * max_len
    prev = payloads[0].ljust(max_len, b"\x00")

    for p in payloads[1:]:
        cur = p.ljust(max_len, b"\x00")
        for i in range(max_len):
            if cur[i] != prev[i]:
                changed[i] = True
        prev = cur

    return [i for i, c in enumerate(changed) if c]

def main():
    path = "candump.log"  # 改成你的文件名
    frames = parse_log(path)
    print(f"[+] Loaded frames: {len(frames)}")

    freq = id_frequency(frames)
    top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]

    print("\n[+] Top 10 IDs by approx frequency (frames/sec):")
    for can_id, f in top:
        print(f"  ID 0x{can_id:03X}  ~ {f:.2f} fps")

    # 对 Top3 做变化字节扫描
    print("\n[+] Changing byte positions for Top3:")
    for can_id, _ in top[:3]:
        ch = changing_bytes(frames, can_id)
        print(f"  ID 0x{can_id:03X} changed bytes: {ch}")

if __name__ == "__main__":
    main()
