# ARP Network Mapper

A Python tool that scans a local network using ARP (Address Resolution Protocol) and displays the IP and MAC addresses of responding devices.

I wanted to see how ARP works in practice, so I built a scanner that discovers local network interfaces, calculates their subnets and sends ARP requests to identify devices.

## What it does

- Detects available network interfaces
- Retrieves IPv4 addresses, MAC addresses and subnet information
- Lets the user select which interface to scan
- Sends ARP requests and collects responses
- Displays discovered IP and MAC addresses
- Removes duplicate IP entries and sorts the results
- Asks for confirmation before scanning larger networks
- Handles invalid selections and permission errors

## Built with

Python, Scapy, psutil, ipaddress and socket.

Developed and tested on Ubuntu.

## How to run

Install the required dependencies:

```bash
python3 -m pip install scapy psutil
```

Run the scanner:

```bash
sudo python3 ARP_Network_Mapping.py
```

Select the network interface you want to scan.

To run the automated tests:

```bash
python3 ARP_Network_Mapping.py --test
```

## What I found interesting

While testing the scanner on my home network, I noticed that several IP addresses were returning the same MAC address.

I investigated this further using Linux networking commands, including `ip neigh` and `ping`.

Some addresses responded immediately, another had unusually high response times, and one didn't respond to ping at all despite appearing in the ARP scan.

It was interesting to see how different the results could be depending on the protocol being used, and why multiple IP addresses resolving to one MAC doesn't necessarily mean they belong to the same physical device.

## Limitations

The scanner works with IPv4 and ARP on local networks. It cannot guarantee that every connected device will be discovered or identify the exact physical device behind an IP address.

ARP scanning requires appropriate permissions on Linux.

Only use it on networks you own or have permission to scan.

## Next

Build a separate ICMP scanner and compare the results with ARP discovery.
