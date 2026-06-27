"""
CloudShield AI - Synthetic Dataset Generator
Generates realistic-looking network traffic logs with labeled attack types,
modeled loosely on NSL-KDD / CIC-IDS style feature distributions, without
requiring any external dataset download. Used as the default demo dataset
and as a reliable fallback if a user-uploaded file fails validation.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta

ATTACK_TYPES = [
    "DDoS", "DoS", "Brute Force", "Port Scan",
    "SQL Injection", "Botnet", "Malware", "Phishing", "Unknown Threat",
]

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]

# Rough per-attack-type behavioral profiles: (bytes_sent mean/std, bytes_received mean/std,
# duration mean/std, dominant protocols)
ATTACK_PROFILES = {
    "Normal":          dict(bs=(800, 400), br=(1200, 600), dur=(5, 3), proto=["TCP", "HTTPS", "HTTP", "UDP"]),
    "DDoS":            dict(bs=(50, 30),    br=(20, 15),    dur=(0.2, 0.1), proto=["UDP", "ICMP"]),
    "DoS":             dict(bs=(100, 50),   br=(30, 20),    dur=(0.5, 0.3), proto=["TCP", "UDP"]),
    "Brute Force":     dict(bs=(150, 60),   br=(100, 40),   dur=(1, 0.5),   proto=["TCP", "HTTPS"]),
    "Port Scan":       dict(bs=(40, 20),    br=(10, 8),     dur=(0.1, 0.05), proto=["TCP"]),
    "SQL Injection":   dict(bs=(600, 300),  br=(400, 200),  dur=(2, 1),     proto=["HTTP", "HTTPS"]),
    "Botnet":          dict(bs=(300, 150),  br=(250, 100),  dur=(8, 4),     proto=["TCP", "UDP"]),
    "Malware":         dict(bs=(900, 400),  br=(1500, 700), dur=(10, 5),    proto=["TCP", "HTTPS"]),
    "Phishing":        dict(bs=(500, 250),  br=(700, 300),  dur=(3, 1.5),   proto=["HTTP", "HTTPS"]),
    "Unknown Threat":  dict(bs=(400, 300),  br=(400, 300),  dur=(4, 3),     proto=PROTOCOLS),
}


def _random_ip(rng, internal=False):
    if internal:
        return f"10.0.{rng.integers(0, 255)}.{rng.integers(1, 255)}"
    return f"{rng.integers(1, 223)}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 255)}"


def generate_synthetic_logs(n_rows=2000, attack_ratio=0.22, seed=None) -> pd.DataFrame:
    """
    Generate a synthetic security log DataFrame with the schema expected
    by the app: timestamp, source_ip, destination_ip, protocol, bytes_sent,
    bytes_received, connection_duration, attack_type.
    """
    rng = np.random.default_rng(seed)
    n_attacks = int(n_rows * attack_ratio)
    n_normal = n_rows - n_attacks

    rows = []
    start_time = datetime.now() - timedelta(hours=24)

    # A small pool of "noisy" source IPs that repeatedly attack, to make
    # the Top Source IPs / leaderboard views meaningful
    noisy_attackers = [_random_ip(rng) for _ in range(max(3, n_attacks // 40))]

    def make_row(label, t_offset):
        profile = ATTACK_PROFILES[label]
        bs = max(1, rng.normal(*profile["bs"]))
        br = max(1, rng.normal(*profile["br"]))
        dur = max(0.01, rng.normal(*profile["dur"]))
        protocol = rng.choice(profile["proto"])
        if label != "Normal" and rng.random() < 0.6 and noisy_attackers:
            src_ip = rng.choice(noisy_attackers)
        else:
            src_ip = _random_ip(rng)
        dst_ip = _random_ip(rng, internal=True)
        ts = start_time + timedelta(seconds=int(t_offset))
        return {
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "bytes_sent": round(bs, 2),
            "bytes_received": round(br, 2),
            "connection_duration": round(dur, 3),
            "attack_type": label,
        }

    # Spread events across 24h, attacks slightly clustered to create timeline spikes
    normal_offsets = rng.uniform(0, 86400, n_normal)
    for off in normal_offsets:
        rows.append(make_row("Normal", off))

    attack_labels = rng.choice(ATTACK_TYPES, size=n_attacks)
    # cluster attacks into a handful of bursts
    n_bursts = max(1, n_attacks // 50)
    burst_centers = rng.uniform(0, 86400, n_bursts)
    for i, label in enumerate(attack_labels):
        center = burst_centers[i % n_bursts]
        off = np.clip(rng.normal(center, 600), 0, 86400)
        rows.append(make_row(label, off))

    df = pd.DataFrame(rows)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def get_sample_csv_bytes(n_rows=500, seed=42) -> bytes:
    """Convenience helper for the downloadable sample dataset."""
    df = generate_synthetic_logs(n_rows=n_rows, seed=seed)
    return df.to_csv(index=False).encode("utf-8")
