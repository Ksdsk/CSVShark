# File name: main.py
# Author: Daniel Kang
# Date: 2022-07-07
# Description: Main file for CSVShark.
# Version: 1.0
# License: none
# Python Version: 3.10.5
# -----------------------------------------------------------------------------

# Importing libraries
import pyshark
import csv

# Read in the packet file
cap = pyshark.FileCapture('./samples/manual_cap1.pcap')

# Write the packets to a CSV file
with open('data.csv', 'a') as csvfile:

    writer = csv.writer(csvfile)


    # ENABLE THIS LINE TO WRITE THE HEADER
    # writer.writerow(['Time', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Source Port', 'Destination Port', 'TCP Size', 'Safe'])
    

    # Write the packets to the CSV file if possible
    for pkt in cap:
        try:
            writer.writerow([pkt.sniff_timestamp, pkt.ip.src, pkt.ip.dst, pkt.ip.proto, pkt.length, pkt.tcp.srcport, pkt.tcp.dstport, pkt.tcp.len, "Yes"])
        except Exception as e:
            print(e) 