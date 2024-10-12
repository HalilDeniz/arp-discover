# arp-discover
ARP discovery tool written in python and scapy.


## Installation
1. Install scapy<br/>
```bash
sudo apt install python3-scapy
```
2. clone the repository
```bash
git clone https://github.com/user-at-host/arp-discover.git

cd arp-discover
```
3. Install requirements
```bash
sudo pip3 install requirements.txt
```
4. Set permissions
```bash
chmod u+x arp-discover.py
```
5. Run
```bash
sudo ./arp-discover.py
```

## Usage
```bash
python3 main.py --help    
usage: main.py [-h] [-p] [-a] -i INTERFACE [--protocol PROTOCOL] [--ip-range IP_RANGE] [--timeout TIMEOUT] [--speed SPEED]

Network ARP Scanner and Sniffer Tool

options:
  -h, --help            show this help message and exit
  -p, --passive         Run in passive mode (default)
  -a, --active          Run in active mode (ARP scan)
  -i INTERFACE, --interface INTERFACE
                        Specify the network interface (e.g., eth0, wlan0)
  --protocol PROTOCOL   Specify the protocol to filter during sniffing (default is 'arp')
  --ip-range IP_RANGE   Specify a custom IP range for ARP scanning (e.g., 192.168.1.0/24)
  --timeout TIMEOUT     Timeout in seconds for ARP scan (default is 2 seconds)
  --speed SPEED         Speed (time in seconds) between each ARP request (default is 0.5 seconds)
```
