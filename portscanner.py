"""
    Simple Scapy Port Scanner
"""

from scapy.all import TCP, IP, sr1, send, ARP, Ether, srp, srp1
import sys
from argparse import ArgumentParser
import math


def clear_line():
    print("\033[2K", end="", flush=True)


def progress(percent, width):
    bars = math.floor(percent * width)

    print("\r[" + "#" * bars + " " * (width - bars) + "] %d%% Complete" %
          math.floor((percent * 100)), end="", flush=True, file=sys.stderr)


def who_has(ip):

    print("Who has %s ?\n" % ip)

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), verbose=0)

    if len(ans) == 0:
        return ""

    return ans[0].answer[ARP].hwsrc


def unpack_response(r):
    ans, _ = r

    print(ans)
    return ans[0].answer


def syn_scan(target, start, end, timeout=0.5):

    target_mac = who_has(target)

    for p in range(start, end + 1):

        packet = Ether(dst=target_mac)/IP(dst=target)/TCP(dport=p, flags="S")

        response = srp(packet, timeout=timeout, verbose=0)

        if response is None:
            print("No response")
            yield (p, False)
            continue

        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            yield (p, True)
        else:
            yield (p, False)


def idle_scan(target: str, victim: str, start: int, end: int, timeout: float):
    victim_mac = who_has(victim)
    print(victim_mac, flush=True)
    for p in range(start, end + 1):

        synack = Ether(dst=victim_mac)/IP(dst=victim) / \
            TCP(sport=12345, dport=123, flags="SA")

        r = srp(synack, timeout=timeout)
        print("Sent initial SYNACK", flush=True)

        if r is None:
            yield (p, False)
            continue

        r = unpack_response(r)

        if r.haslayer(TCP) and r[TCP].flags != 0x04:
            print("error: idle scan: expected initial SYN-ACK to repond with RST")

        intial_ipid = r.id

        syn = IP(src=victim, dst=target)/TCP(sport=12345, dport=p, flags="S")

        send(syn)
        print("Sent forged SYN", flush=True)

        synack = Ether(dst=victim_mac)/IP(dst=victim, id=synack.id + 1) / \
            TCP(sport=12345, dport=123, flags="SA")

        r = srp(synack, timeout=timeout)
        r = unpack_response(r)

        print("Sent final SYNACK", flush=True)

        if r is None:
            yield (p, False)
            continue

        if r.haslayer(TCP) and r[TCP].flags != 0x04:
            print("error: idle scan: expected final SYN-ACK to repond with RST")

        final_ipid = r.id

        ipid_diff = final_ipid - intial_ipid

        print(intial_ipid, final_ipid)

        if ipid_diff == 2:
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
parser.add_argument("--type", nargs=1, action="store", required=True, help="Type of scan: syn, idle")
parser.add_argument("--target", nargs=1, action="store",
                    required=True, help="target user IP")
parser.add_argument("--victim", nargs=1, action="store", help="victim user IP (only for idle scan)")
parser.add_argument("--startport", nargs=1, action="store",
                    required=True, type=int, help="starting port")
parser.add_argument("--endport", nargs=1, action="store",
                    required=True, type=int, help="ending port")
parser.add_argument("--timeout", nargs=1, action="store",
                    type=float, help="amount of time in seconds to wait for reply")


args = parser.parse_args(sys.argv[1:])
scan = args.type[0]
target = args.target[0]
victim = args.victim[0] if args.victim is not None else None
start_port = args.startport[0]
end_port = args.endport[0]
timeout = args.timeout[0] if args.timeout is not None else 0.5


if scan == "syn":

    for (p, active) in syn_scan(target, start_port, end_port, timeout=timeout):

        completed = (p - start_port + 1)/(end_port - start_port + 1)

        if active:
            clear_line()
            print("\rPort %d is active." % p)

        progress(completed, min(80, end_port - start_port + 1))

elif scan == "idle":
    
    for (p, active) in idle_scan(target, victim, start_port, end_port, timeout):

        completed = (p - start_port + 1)/(end_port - start_port + 1)

        if active:
            clear_line()
            print("\rPort %d is active." % p)

        progress(completed, min(80, end_port - start_port + 1))
