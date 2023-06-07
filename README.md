# GITA (Grupo de Investigación en Telecomunicaciones Aplicadas) 

This repository presents GooseFlowMeter, a flow generator modified to satisfy the needs of the GITA research group. This project takes the basis from [Python Wrapper CICflowmeter](https://github.com/datthinh1801/cicflowmeter) and [Goosestalker](https://github.com/cutaway-security/goosestalker/blob/main/README.md) to build a traffic generator capable of working with Goose traffic defined by the IEC61850 standard.

## GooseFlowMeter

GooseFlowMeter (CICFlowMeter + Goosestalker) is a project adapted to fulfill the needs of the cybersecurity project from the GITA research group at the Universidad de Antioquia. The application permits to capture Goose packets and joint them into flows to perform further analysis and traffic classification.


### Installation
```sh
git clone https://github.com/SantiagoGuiral/GooseFlowMeter.git
cd cicflowmeter
sudo python3 setup.py install
```

### Usage
```sh
usage: gooseflowmeter [-h] (-i INPUT_INTERFACE | -f INPUT_FILE) [-c] [-u URL_MODEL] output

positional arguments:
  output                output file name (in flow mode) or directory (in sequence mode)

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_INTERFACE    capture online data from INPUT_INTERFACE
  -f INPUT_FILE         capture offline data from INPUT_FILE
  -c, --csv, --flow     output flows as csv
```

Generate CSV file from PCAP with Goose packets:

```
gooseflowmeter -f goose.pcap -c goose_flows.csv
```

Capture Goose packets from network interface and convert them into CSV file (**need root permission**):

```
gooseflowmeter -i eth0 -c goose_flows.csv
```

### References

- Reference: https://www.unb.ca/cic/research/applications.html#CICFlowMeter
- Reference: https://github.com/datthinh1801/cicflowmeter
- Reference: https://github.com/cutaway-security/goosestalker

### Contact

- Contact: Santiago Rios Guiral (santiago.riosg@udea.edu.co)
