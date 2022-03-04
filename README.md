# Scanner
Evolving network scanner based on the namp library

## Description
Nmap is one of the most well known tools in a hackers arsenal. 
Although it can be powerful it's quite simple in terms of architecture. 

This script in particular reveals a nodes ports number and status for now. 

## Installation
- Install Python3

## Usage
- script -i ip_address -p port_range -t type_scan
  - Legend
    - ip_address = 192.168.1.60
    - port_range = 1-1024
    - type_Scan = TCP Scan

## Scans

### TCP Scan
A standard scan that send a TCP to node with a SYN flag set. 

### SYN Scan
Similar to the TCP scan but the RST flag is set. Meaning that there is no response message from the node
which decreased scan time

### UDP Scan
UDP scan is quick but very unreliable. The UDP protocol does not contain as many checks in regards to the packets reaching thier destination. 
Due to this there may be some false positives sent back to the user of the script.

### Null Scan
A Scan that is sent without any flags. Technically the node receiving the scan should respod with a RST flag meaning the port is closed, otherwise it's open or filtered.

### Fin Scan
With a fin Scan the FIN flag is set, giving a smilar to result as the Null Scan which would send back an RST revealing a closed port. 

### Xmas Scan
The Xmas scan has PSH, URG and FIN flags set, resulting in RST response from a closed port. 


