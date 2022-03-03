#!/usr/bin/env python
# Name:     scanner
# Purpose:  Python to scan a host on your network with the nmap library 
# By:       Jordan Trelford
# Date:     03.03.22
# Modified  02.03.22
# Rev Level 0.1
# ----------------------------------------------

import nmap
import argparse

scanner = nmap.PortScanner()

class Scan:
    def __init__(self, ip_addr, range, stype):
        self.ip_addr = ip_addr
        self.range = range 
        self.stype = stype
    
    # Define scan type
    def scan_type(self): 
        if self.scan_type == 'TCPSYNScan':
            return '-v -sT'
    
    # print out response of host scan
    def response(self):
        print("Nmap version: ", scanner.nmap_version())
        scanner.scan(self.ip_addr, self.range, self.stype)
        
        try: 
            print("IP Status:", scanner[self.ip_addr].state())

            if str(scanner[self.ip_addr].all_protocols()) == '[]': 
                print('All Ports Are Closed')
            else: 
                print(scanner[self.ip_addr].all_protocols())

            for proto in scanner[self.ip_addr].all_protocls(): 
                print('Protocol is ')

            mac = scanner[self.ip_addr]['addresses']['mac']
            print("Mac Address: " , scanner[self.ip_addr]['addresses']['mac'])
            print("Machine: ", scanner[self.ip_addr]['vendor'][mac])

        except:
            print("Host is down...")
            


parser = argparse.ArgumentParser(description='Scan A Host On The Network')
parser.add_argument('-i', '--ip', 
                    metavar='', 
                    required=True , 
                    type=str, 
                    help='ip address to scan')


parser.add_argument('-p', '--port', 
                    metavar='', 
                    required=True, 
                    type=str, 
                    help='ports from 1-p to scan')

parser.add_argument('-t', '--type', 
                    metavar='', 
                    required=True, 
                    type=str, 
                    help='scan type',
                    )
args = parser.parse_args()


if __name__ == '__main__':
    print(args.type)
    host = Scan(args.ip, args.port, args.type)
    host.response()