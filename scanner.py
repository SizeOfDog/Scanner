#!/usr/bin/env python
# Name:     scanner
# Purpose:  Python to scan a host on your network with the nmap library 
# By:       Jordan Trelford
# Date:     03.03.22
# Modified  02.04.22
# Rev Level 0.2
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
        if self.stype == 'TCP Scan':
            return '-v -sT'
        elif self.stype == "SYN Scan": 
            return '-v -sS'
        elif self.stype == "UDP Scan": 
            return '-v -sU'
        elif self.stype == "Null Scan": 
            return '-v -sN'   
        elif self.stype == "FIN Scan": 
            return '-v -sF'
        elif self.stype == "Xmas Scan": 
            return '-v -sX'     
    
    
    # print out response of host scan
    def response(self):
        print("\nNmap version: ", scanner.nmap_version())
        scanner.scan(self.ip_addr, self.range, self.scan_type())
        
        try: 
            print("IP Status:", scanner[self.ip_addr].state())

            if str(scanner[self.ip_addr].all_protocols()) == '[]': 
                print('All Ports Are Closed')
            else: 
                # print(scanner[self.ip_addr].all_protocols())
                print('')

            for proto in scanner[self.ip_addr].all_protocols(): 
                print('Protocol: %s' % proto)

                target = scanner[self.ip_addr][proto].keys()  

                for port in sorted(target): 
                    print("Port: %s State: %s" % (port,  scanner[self.ip_addr][proto][port]['state']))

            

            mac = scanner[self.ip_addr]['addresses']['mac']
            print("Mac Address: " , scanner[self.ip_addr]['addresses']['mac'])
            print("Machine: ", scanner[self.ip_addr]['vendor'][mac])

        except Exception as e:
            print(e)
            


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
    host = Scan(args.ip, args.port, args.type)
    host.response()