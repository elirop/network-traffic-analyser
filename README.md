# Network Traffic Analyser

This beginner project turns a Wireshark capture into a Markdown report. It uses
TShark (included with Wireshark) and Python 3; no Python packages are needed.

## Mac setup

Install Python 3 from https://www.python.org/downloads/macos/ and Wireshark from
https://www.wireshark.org/download.html . Install **ChmodBPF** from the Wireshark
disk image to permit capturing. Capture on the active Wi-Fi interface, save
`my-traffic.pcapng` next to this script, then run:

```bash
python3 analyse.py my-traffic.pcapng
```

Open `traffic-report.md` to see the results.

## Windows setup

1. Install Python from https://www.python.org/downloads/windows/ . Open PowerShell
   and check `py -3 --version`. If that command is unavailable, try
   `python --version` and use `python` instead of `py -3` in the commands below.
2. Install Wireshark from https://www.wireshark.org/download.html . Keep **TShark**
   selected in the component list and **Npcap** selected when prompted. Npcap
   allows live packet capture.
3. Extract this ZIP to a convenient folder, such as `Downloads\mac-traffic-analyser`.
4. Open Wireshark, double-click the active Wi-Fi or Ethernet interface, browse
   a few websites, then stop the capture. Save the file as `my-traffic.pcapng`
   inside the extracted project folder.
5. Open that folder in File Explorer. Click the address bar, type `powershell`,
   and press Enter. Run:

```powershell
py -3 .\analyse.py .\my-traffic.pcapng
```

Open `traffic-report.md` in that folder. It shows protocols, top destinations,
IP conversations, DNS queries, traffic volume by minute, and a retransmission
count. You can choose another report path with `--output report.md`.

If TShark is not found, verify its usual installation path:

```powershell
& 'C:\Program Files\Wireshark\tshark.exe' --version
```

## What to look for

- Is `DNS` present after loading websites?
- Which destination IPs account for the most captured bytes?
- Do traffic spikes correspond to what you did on the laptop?
- Are there TCP retransmissions? Compare with Wireshark's
  `tcp.analysis.retransmission` display filter before drawing conclusions.

The destination table measures captured bytes *toward* each IP. The conversation
table counts captured bytes in both directions. The capture covers what the chosen
interface sees, mainly your laptop's own traffic; it is not a whole-home-network
view. Time labels use UTC so captures are consistent across time zones.

Capture only traffic you are permitted to inspect. Packet files can contain
private data; avoid sharing raw captures publicly.

## Share the code on GitHub

Create an empty repository named `network-traffic-analyser` on GitHub, without
adding GitHub's starter README or `.gitignore`. Then run these commands in
Terminal from this project folder:

```bash
git init
git add README.md analyse.py .gitignore
git commit -m "Add network traffic analyser"
git branch -M main
git remote add origin https://github.com/elirop/network-traffic-analyser.git
git push -u origin main
```

The `.gitignore` excludes packet captures and generated reports. Check
`git status` before every push and never add personal captures to a public repo.
