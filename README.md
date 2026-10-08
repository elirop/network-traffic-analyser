Network Traffic Analyser
A small Python project I'm using to practise packet analysis with Wireshark.
The script reads a saved capture through TShark and puts the results into a Markdown report. I tested it on my Mac using traffic captured while browsing.
What it reports
- Packet count and capture duration
- Protocol counts
- Destination IPs ranked by captured bytes
- The busiest IP pairs
- DNS queries
- Traffic volume per minute
- TCP retransmission count
Requirements
- Python 3
- Wireshark with TShark installed
No extra Python packages are needed.
On macOS, install ChmodBPF from the Wireshark installer to enable packet capture. On Windows, install Npcap when prompted.
Run it
Clone the repository:
git clone https://github.com/elirop/network-traffic-analyser.git
cd network-traffic-analyser
Capture some traffic in Wireshark, stop the capture and save it in the project folder as my-traffic.pcapng.
On Mac:
python3 analyse.py my-traffic.pcapng
On Windows:
py -3 .\analyse.py .\my-traffic.pcapng
Open traffic-report.md to see the results. To use a different output filename:
python3 analyse.py my-traffic.pcapng --output report.md
Reading the results
The destination table includes traffic arriving at your own laptop. The conversation table combines both directions between each IP pair. Byte counts use captured frame lengths, including headers.
All times are in UTC. The report only covers the captured traffic, and retransmissions on their own don't confirm a network fault.
Packet captures and the default report are excluded from Git by .gitignore.
