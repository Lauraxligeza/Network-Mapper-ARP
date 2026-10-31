import socket, sys, argparse
import psutil, ipaddress
from scapy.all import ARP, Ether, srp
from unittest.mock import patch

def get_interfaces():
    nets = []
    skip = ('tun', 'tap', 'docker', 'veth', 'br-', 'virbr')
    stats = psutil.net_if_stats()
    
    for iface, addrs in psutil.net_if_addrs().items():
        if any(iface.startswith(s) for s in skip): 
            continue
        if iface in stats and not stats[iface].isup: 
            continue
            
        mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
        
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith('127.'):
                try:
                    net = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
                    hosts = net.num_addresses - 2 if net.num_addresses > 2 else max(0, net.num_addresses)
                    nets.append({
                        "iface": iface, "mac": mac, "ip": a.address,
                        "mask": a.netmask, "prefix": net.prefixlen,
                        "cidr": str(net), "hosts": hosts
                    })
                except ValueError as e:
                    print(f"[-] Error parsing network for {iface}: {e}")
    return nets

def process_arp_results(res):
    devs = {r.psrc: r.hwsrc for s, r in res}
    return sorted([{"ip": ip, "mac": mac} for ip, mac in devs.items()], 
                  key=lambda d: ipaddress.ip_address(d["ip"]))

def scan_network(cidr, iface):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr), iface=iface, timeout=2, verbose=0)
        return process_arp_results(ans)
    except PermissionError:
        print("[-] Need root / sudo privileges for ARP scanning.")
    except Exception as e:
        print(f"[-] Scan error: {e}")
    return None

def confirm_large_scan(net):
    if net['prefix'] >= 24: 
        return True
    ans = input(f"[!] Warning: /{net['prefix']} is a large subnet (~{net['hosts']} hosts). Proceed? (y/n): ").strip().lower()
    return ans == 'y'

def run_unit_tests():
    print("[*] Running tests...")
    big = {"prefix": 16, "hosts": 65534}
    small = {"prefix": 24, "hosts": 254}
    
    with patch('builtins.input', return_value='n'):
        assert confirm_large_scan(big) is False
    with patch('builtins.input', return_value='y'):
        assert confirm_large_scan(big) is True
    with patch('builtins.input') as p:
        assert confirm_large_scan(small) is True
        p.assert_not_called()
    print("[+] All tests passed successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="Run tests")
    args = parser.parse_args()
    
    if args.test:
        run_unit_tests()
        sys.exit(0)
    
    print("[*] Finding active network interfaces...\n")
    nets = get_interfaces()
    
    if not nets:
        print("[-] No valid IPv4 interfaces found.")
        sys.exit(1)
        
    print("Available interfaces:")
    for i, n in enumerate(nets, 1):
        print(f"  [{i}] {n['iface']} ({n['ip']} - {n['cidr']})")
        
    try:
        choice = int(input("\nSelect interface to scan: ")) - 1
        if choice < 0 or choice >= len(nets):
            print("[-] Invalid selection number.")
            sys.exit(1)
        net = nets[choice]
    except ValueError:
        print("[-] Please enter a valid integer.")
        sys.exit(1)
        
    print(f"\n[*] Target: {net['cidr']} on {net['iface']}")
    
    if not confirm_large_scan(net):
        sys.exit("[-] Aborted by user.")
        
    print(f"[*] Scanning {net['cidr']}...")
    devices = scan_network(net['cidr'], net['iface'])
    
    if devices is not None:
        print(f"\n[*] Found {len(devices)} device(s):")
        print(f"{'IP Address':<18} | {'MAC Address'}")
        print("-" * 35)
        for d in devices:
            print(f"{d['ip']:<18} | {d['mac']}")