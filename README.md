# Network Traffic Analyser

A small Python project I'm using to practise packet analysis with Wireshark.

It reads a saved capture through TShark and produces a traffic report. I tested it on my Mac using traffic captured while browsing.

## What it reports

- Packet count and capture duration
- Protocol counts
- Destination IPs ranked by captured bytes
- The busiest IP pairs
- DNS queries
- Traffic volume per minute
- TCP retransmissions

## Requirements

- Python 3
- Wireshark with TShark installed

No extra Python packages are needed.

**Mac:** Install ChmodBPF from the Wireshark installer to enable capture.

**Windows:** Install Npcap when prompted.

## Running the analyser

Clone the project:

```bash
git clone https://github.com/elirop/network-traffic-analyser.git
cd network-traffic-analyser
```

Capture traffic in Wireshark, stop the capture, and save it in the project folder as `my-traffic.pcapng`.

### Mac

```bash
python3 analyse.py my-traffic.pcapng
```

### Windows

```powershell
py -3 .\analyse.py .\my-traffic.pcapng
```

Open `traffic-report.md` to view the results.

## Understanding the report

- The destination table includes traffic received by your own laptop.
- The conversation table combines traffic in both directions.
- Byte counts include packet headers.
- Times are shown in UTC.
- Retransmissions alone don't confirm a network problem.

Packet captures and the default report are excluded from Git by `.gitignore`.
