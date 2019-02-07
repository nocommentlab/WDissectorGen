#!/usr/bin/env python
# coding: utf-8

"""
sender.py
This file is part of Wireshark Dissector Generator(WDissectorGen).
Wireshark Dissector Generator(WDissectorGen) is free software: 
you can redistribute it and/or modify it under the terms of the 
GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.
Wireshark Dissector Generator(WDissectorGen) is distributed in the hope 
that it will be useful,but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with Wireshark Dissector Generator(WDissectorGen).  
If not, see <http://www.gnu.org/licenses/>.
"""

import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Payload composition:
# 32bit Sequence Counter
# 16bit Type Field
# 8bit Checksum Field
# 7byte Name Field
protocol_payload = [0x00, 0xC0, 0xFF, 0XEE, 0x0A, 0x0B, 0xFE,0x61,0x6e,0x74,0x6f,0x6e,0x69,0x6f]
my_protocol = bytearray(protocol_payload)
sock.sendto(my_protocol, ("127.0.0.1", 8888))
