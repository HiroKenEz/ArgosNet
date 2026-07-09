"""Régénère les captures d'exemple à partir des fixtures.

Usage :  python tests/generate_pcaps.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from scapy.utils import wrpcap  # noqa: E402

from fixtures import build_attack_packets, build_sample_packets  # noqa: E402

HERE = os.path.dirname(__file__)


def main() -> None:
    wrpcap(os.path.join(HERE, "sample.pcap"), build_sample_packets())
    wrpcap(os.path.join(HERE, "attack_sample.pcap"), build_attack_packets())
    print("sample.pcap et attack_sample.pcap régénérés.")


if __name__ == "__main__":
    main()
