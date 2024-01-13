# RDPMITM-IPV4Measurment

基于 "Looking for Honey Once Again: Detecting RDP and SMB Honeypots on the Internet" IPV4测量代码，我们只收集tls特征和RTT特征，用于检测RDP MITM TOOL。

## How to use

Our scanners are supposed to be used with the ZMap internet scanner. Therefore, to perform a scan  you can e.g. perform the follwoing command:

    zmap -p 3389 | python3 RDP_scan_asyncio.py


