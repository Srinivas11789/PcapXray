# PcapXray [![Build Status](https://travis-ci.org/Srinivas11789/PcapXray.svg?branch=master)](https://travis-ci.org/Srinivas11789/PcapXray) [![codecov](https://codecov.io/gh/Srinivas11789/PcapXray/branch/master/graph/badge.svg)](https://codecov.io/gh/Srinivas11789/PcapXray)
    A Network Forensics Tool - To visualize a Packet Capture offline as a Network Diagram including device identification, highlight important communication and file extraction
![Alt text](/logo.png?width=20px "PcapXray")
## PcapXray Design Specification

### Goal:
  Given a Pcap File, plot a network diagram displaying hosts in the network, network traffic, highlight important traffic and Tor traffic as well as potential malicious traffic including data involved in the communication.

### Problem:
* Investigation of a Pcap file takes a long time given initial glitch to start the investigation
*	Faced by every forensics investigator and anyone who is analyzing the network

* Location: https://github.com/Srinivas11789/PcapXray

### Solution: Speed up the investigation process
* Make a network diagram with the following features from a Pcap file
Tool Highlights:
* Network Diagram – Summary Network Diagram of full network
* Information: 
  * Web Traffic with Server Details
  * Tor Traffic
  * Possible Malicious traffic
  * Data Obtained from Packet in Report – Device/Traffic/Payloads
  * Device Details
  
### Tool Image:
![Alt text](/Samples/screen1_2.0.png?raw=true)

![Alt text](/Samples/screen2_2.0.png?raw=true)

### Components:
*	Network Diagram 
* Device/Traffic Details and Analysis
* Malicious Traffic Identification
* Tor Traffic
* GUI – a gui with options to upload pcap file and display the network diagram

### Python Libraries Used:  - All these libraries are required for functionality
* Tkinter and TTK – Install from pip or apt-get – Ensure Tkinter and graphviz is installed (Most Linux contain by default) 
  * apt install python-tk
  * apt install graphviz
* All these are included in the requirements.txt file
  * Scapy – rdpcap to read the packets from the pcap file 
  *	Ipwhois – to obtain whois information from ip
  *	Netaddr – to check ip information type
  *	Pillow – image processing library
  *	Stem – tor consensus data fetch library
  *	pyGraphviz – plot graph
  *	Networkx – plot graph
  *	Matplotlib – plot graph
  
### Demo
![Alt text](/Samples/demo2.0.gif?raw=true)

### Getting started:
* Clone the repository
* pip install -r requirements.txt
* python Source/main.py

### Additional Information:
* Tested on Linux
* Options for Traffic include - Web (HTTP and HTTPS), Tor, Malicious
 
### Challenges:
  * Unstability of the TK GUI:
    * Decision on the GUI between Django and TK, settled upon tk for a simple local interface, but the unstability of the tk gui caused a number of problems
  * Graph Plotting:
    * Plotting a proper network graph which is readable from the data obtained was quite an effort, used different libraries to arrive at one.
  * Performance and Timing:
    * The performance and timing of the total application was a big challenge with different data gathering and output generation

### Known Bugs:
* Memory Hogging
  * Sometimes memory hogging occurs when lower RAM is present in the system as the data stored in the memory from the pcap file is huge
  * Should be Fixed by moving data into a database than the memory itself
* Race Condition
  * Due to mainloop of the TK gui, other threads could undergo a race condition
  * Should be fixed by moving to a better structured TK implementation or Web GUI
* Tk GUI Unstability:
  * Same reason as above
* Code:
  * clumsy and unstructured code flow

*	Current Fix in rare occasions: If any of the above issue occurs the progress bar keeps running and no output is generated, a restart of the app would be required.

### PcapXray 2.0 
* Includes zoom feature
* Improves usability with a Browse files feature
* Includes some bug fixes

# Immediate Future Tasks:
* Clean up code - beautify code base from being a prototype

### Future:
*   Structured and clean code flow
*	Change the database from JSON to sqlite or prominent database, due to memory hogging
*	Change fronend to web based such as Django
*	Make the application more stable
*   More protocol support

[![Analytics](https://ga-beacon.appspot.com/UA-114681129-1/PcapXray/readme)](https://github.com/igrigorik/ga-beacon)
