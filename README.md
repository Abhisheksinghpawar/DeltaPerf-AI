# 🚀 DeltaPerf AI

**DeltaPerf AI** is a Python-powered tool for analyzing `.pcap` and `.pcapng` network capture files with a focus on latency detection, protocol behavior, and AI-powered summarization. Whether you're a network engineer, security analyst, or curious hacker, DeltaPerf AI transforms raw packet data into actionable insights.

---

## 🔍 Features

- 📁 **Multi-file PCAP Analysis** – Automatically scans and processes all capture files in a directory.
- 🔥 **Latency Detection** – Flags high-latency events (>1s) and extreme spikes (>10s).
- 🎨 **Color-Coded CLI Dashboard** – Uses `colorama` and `tabulate` for clean, readable summaries.
- 🤖 **AI-Powered Summaries** – Integrates with [Ollama](https://ollama.com) to generate expert-level insights.
- ⚠️ **Anomaly Detection** – Optional deep dive into suspicious patterns and performance issues.
- 🧠 **Interactive Prompts** – Choose when to trigger AI analysis or skip it.

---

## 📦 Requirements

- Python 3.8+
- pyshark
- tabulate
- colorama
- requests

Install dependencies:

```bash
pip install pyshark tabulate colorama requests
```

---

## 🛠️ Usage

1. Place your `.pcap` or `.pcapng` files in the working directory.
2. Start your local Ollama server (if using AI features).
3. Run the script:

```bash
python delta_perf_ai.py
```

---

## 📊 Sample Output

### 🎨 Color Legend

Legend: 🔴 >10s  🟡 >1s  🟢 ≤1s  🔵 TCP  🟣 UDP  ⚪ Other


### 📁 File Summary


📁 Available Capture Files: 3

📦 Total Packets Analyzed: 45,320

🔥 Latency Events (>1s): 87

🧮 Average Delta Time (s): 0.002345


### 🧠 AI Summary (via Ollama)

🤖 Model: tinyllama:1.1b
🕒 Generated: 2025-08-08 15:04 CDT
📊 Events Analyzed: 1,204

Summary:
- Latency spikes observed in TCP traffic between 192.168.1.10 and 192.168.1.20.
- UDP traffic remained stable with minimal delay.
- No retransmissions or suspicious behavior detected.

## ⚠️ Error Handling

If a file is missing or unreadable:

❌ Error processing file ./captures/fuzz-2006-06-26-2594.pcap: [Errno 2] No such file or directory

If Ollama is not running:

❌ Ollama is not running. Please start Ollama server to use AI features.

## 📈 Future Enhancements

- Export summary to `.txt` or `.csv`
- GUI dashboard with charts
- Real-time packet stream analysis
- Integration with cloud-based capture sources

## 🤝 Contributing

Pull requests and feedback are welcome! Feel free to fork the repo, suggest features, or report bugs.

## 🧠 Built With

- Python
- PyShark
- Tabulate
- Colorama
- Ollama (for AI summaries)

## 📜 License

MIT License — free to use, modify, and share.
