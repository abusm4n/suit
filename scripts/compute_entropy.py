#!/usr/bin/env python3
"""Compute Shannon, Rényi, and Tsallis entropy for raw byte payloads.

Usage:
  - Test with synthetic data: `python3 scripts/compute_entropy.py --test`
  - Compute on a pcap (requires scapy):
    `python3 scripts/compute_entropy.py --pcap path/to/file.pcap --mode session`

The script includes compact implementations and a fallback test that does not require pcaps.
"""
import argparse
import math
from collections import Counter

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = -sum((c/total) * math.log2(c/total) for c in counts.values())
    return ent / 8.0  # normalize by max 8 bits

def renyi_entropy(data: bytes, alpha: float = 2.0) -> float:
    if not data:
        return 0.0
    if alpha == 1.0:
        return shannon_entropy(data)
    counts = Counter(data)
    total = len(data)
    s = sum((c/total)**alpha for c in counts.values())
    ent = (1.0 / (1.0 - alpha)) * math.log2(s)
    return ent / 8.0

def tsallis_entropy(data: bytes, q: float = 1.5) -> float:
    if not data:
        return 0.0
    if q == 1.0:
        return shannon_entropy(data)
    counts = Counter(data)
    total = len(data)
    s = sum((c/total)**q for c in counts.values())
    ent = (1.0 - s) / (q - 1.0)
    # Tsallis output is in different units; normalize by max value for q to keep 0-1 comparability approximately
    # For uniformly distributed 256 symbols, max ent = (1 - 256*(1/256)**q)/(q-1)
    max_ent = (1.0 - 256 * (1.0 / 256.0) ** q) / (q - 1.0)
    return ent / max_ent if max_ent != 0 else 0.0

def entropy_from_bytes(data: bytes, renyi_alpha: float = 2.0, tsallis_q: float = 1.5):
    return {
        "shannon": shannon_entropy(data),
        "renyi": renyi_entropy(data, renyi_alpha),
        "tsallis": tsallis_entropy(data, tsallis_q),
    }

def process_pcap_sessions(pcap_path: str, renyi_alpha: float=2.0, tsallis_q: float=1.5):
    try:
        from scapy.all import rdpcap, Raw
    except Exception as e:
        raise RuntimeError("scapy is required to process pcaps. Install from requirements.") from e
    packets = rdpcap(pcap_path)
    # simple session grouping: aggregate payload per 5-tuple (src,dst,sport,dport,proto)
    sessions = {}
    for pkt in packets:
        try:
            proto = pkt.payload.name
            key = (pkt[0].src, pkt[0].dst, pkt.sport if hasattr(pkt, 'sport') else None,
                   pkt.dport if hasattr(pkt, 'dport') else None, proto)
        except Exception:
            key = ('unknown',)
        raw = None
        try:
            raw = bytes(pkt[Raw].load)
        except Exception:
            raw = b''
        sessions.setdefault(key, bytearray()).extend(raw)
    # compute entropies per session
    results = []
    for key, payload in sessions.items():
        e = entropy_from_bytes(bytes(payload), renyi_alpha, tsallis_q)
        results.append((key, e))
    return results

def run_test():
    print("Running synthetic tests:")
    # uniform distribution over 256 bytes -> max entropy
    uniform = bytes(range(256)) * 4
    print("Uniform 256-symbols ->", entropy_from_bytes(uniform))
    # low-entropy: repeated zeros
    zeros = b'\x00' * 4096
    print("All-zero payload ->", entropy_from_bytes(zeros))
    # mixed
    mixed = (b'\x00' * 1000) + bytes(range(128)) * 2
    print("Mixed payload ->", entropy_from_bytes(mixed))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', help='Path to pcap file')
    parser.add_argument('--mode', choices=['session','raw'], default='session')
    parser.add_argument('--alpha', type=float, default=2.0, help='Rényi alpha')
    parser.add_argument('--q', type=float, default=1.5, help='Tsallis q')
    parser.add_argument('--test', action='store_true', help='Run synthetic tests')
    args = parser.parse_args()
    if args.test:
        run_test()
        return
    if args.pcap:
        res = process_pcap_sessions(args.pcap, args.alpha, args.q)
        for key, e in res:
            print(key, e)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
