"""
    Simple Scapy Port Scanner
"""

from scapy.all import TCP, IP, sr1
import sys
from argparse import ArgumentParser
import math

def clear_line():
    print("\033[2K", end="", flush=True)

def progress(percent, width):
    bars = math.floor(percent * width)
    print("\r[" + "#" * bars + " " * (width - bars) + "] %d%% Complete" %
          math.floor((percent * 100)), end="", flush=True, file=sys.stderr)

def scan_ports(target, start, end, timeout=0.5):

    for p in range(start, end + 1):

        packet = IP(dst=target)/TCP(dport=p, flags="S")

        response = sr1(packet, timeout=timeout, verbose=0)

        if response is None:
            yield (p, False)
            continue

        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            yield (p, True)
        else:
            yield (p, False)

# Print out a cool ASCII art title like all the other cool hacking tools do :)
tool_description = """
  _____           _      _____                                                   
 |  __ \         | |    / ____|                                                  
 | |__) |__  _ __| |_  | (___   ___ __ _ _ __  _ __   ___ _ __       _ __  _   _ 
 |  ___/ _ \| '__| __|  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|     | '_ \| | | |
 | |  | (_) | |  | |_   ____) | (_| (_| | | | | | | |  __/ |     _  | |_) | |_| |
 |_|   \___/|_|   \__| |_____/ \___\__,_|_| |_|_| |_|\___|_|    (_) | .__/ \__, |
                                                                    | |     __/ |
                                                                    |_|    |___/ 
Scans ports using TCP SYN and SYN-ACK packets.
Author: David Yue <davidyue5819@gmail.com>
"""
print(tool_description, file=sys.stderr)
parser = ArgumentParser()
parser.add_argument("--target", nargs=1, action="store", required=True, help="target user IP")
parser.add_argument("--startport", nargs=1, action="store",
                    required=True, type=int, help="starting port")
parser.add_argument("--endport", nargs=1, action="store",
                    required=True, type=int, help="ending port")
parser.add_argument("--timeout", nargs=1, action="store", type=float, help="amount of time in seconds to wait for reply")


args = parser.parse_args(sys.argv[1:])
target = args.target[0]
start_port = args.startport[0]
end_port = args.endport[0]
timeout = args.timeout if args.timeout is not None else 0.5

for (p, active) in scan_ports(target, start_port, end_port, timeout=timeout):

    completed = (p - start_port + 1)/(end_port - start_port + 1)

    if active:
        clear_line()
        print("\rPort %d is active." % p)

    progress(completed, min(80, end_port - start_port + 1))
