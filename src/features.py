from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd


def compute_window_features(packets):
    total_packets = len(packets)
    total_bytes = sum(len(p) for p in packets)

    src_ips = set()
    dst_ips = set()
    src_ports = set()
    dst_ports = set()

    tcp_count = 0
    udp_count = 0
    other_count = 0

    for p in packets:
        if IP in p:
            src_ips.add(p[IP].src)
            dst_ips.add(p[IP].dst)

        if TCP in p:
            tcp_count += 1
            src_ports.add(p[TCP].sport)
            dst_ports.add(p[TCP].dport)
        elif UDP in p:
            udp_count += 1
            src_ports.add(p[UDP].sport)
            dst_ports.add(p[UDP].dport)
        else:
            other_count += 1

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "unique_src_ports": len(src_ports),
        "unique_dst_ports": len(dst_ports),
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "other_count": other_count,
        "avg_packet_size": total_bytes / total_packets if total_packets > 0 else 0,
    }


def extract_features_from_pcap(pcap_path, window_size=60):
    packets = rdpcap(pcap_path)

    if len(packets) == 0:
        return pd.DataFrame()

    rows = []

    # first packet timestamp
    start_time = float(packets[0].time)
    window_start = start_time
    current_window_packets = []

    for p in packets:
        t = float(p.time)

        # if packet still inside current window
        if t - window_start <= window_size:
            current_window_packets.append(p)
        else:
            # close the current window and start a new one
            if current_window_packets:
                feats = compute_window_features(current_window_packets)
                feats["window_start"] = window_start
                rows.append(feats)

            window_start = t
            current_window_packets = [p]

    # handle last window
    if current_window_packets:
        feats = compute_window_features(current_window_packets)
        feats["window_start"] = window_start
        rows.append(feats)

    df = pd.DataFrame(rows)
    return df
