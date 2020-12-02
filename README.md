# arp-discover
ARP discovery tool written in python and scapy.


## Instalation
1. Install scapy<br/>
```bash
sudo apt install python3-scapy
```
2. clone the repository
```bash
git clone https://github.com/gsv-gh/arp-discover.git

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

    usage: arp-discover.py [-h] [-p] [-a]

    optional arguments:
        -h, --help     show this help message and exit
        -p, --passive  Run in passive mode (default)
        -a, --active   Run in active mode (ARP scan)
