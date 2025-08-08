🚀 DeltaPerf AI – Intelligent PCAP Latency Analyzer

DeltaPerf AI is a powerful Python-based tool for analyzing .pcap and .pcapng network capture files with a focus on latency detection and protocol behavior. It combines traditional packet inspection with AI-powered summarization to help network engineers, analysts, and researchers uncover performance bottlenecks and anomalies in real time.

🔍 Key Features
- Multi-file PCAP Analysis: Automatically scans and processes all capture files in the specified directory.
- Latency Detection: Calculates delta times between packets and flags high-latency events (>1s) and extreme latency spikes (>10s).
- Protocol-Aware Insights: Differentiates TCP, UDP, and other protocols with color-coded output for quick visual parsing.
- Interactive Summary Dashboard: Displays a tabulated summary of total files, packets, latency events, and average delta time.
- AI-Powered Summarization: Integrates with Ollama to generate expert-level summaries and anomaly detection reports using models like tinyllama:1.1b.
- User-Friendly CLI: Includes color-coded legends, prompts for deeper insights, and graceful error handling.

🧠 AI Integration

If Ollama is running locally, the tool can generate intelligent summaries of network behavior and optionally perform anomaly detection. This includes identifying unusual latency patterns, retransmissions, and suspicious traffic, with actionable suggestions.

📦 Requirements
- Python 3.8+
- pyshark, tabulate, colorama, requests

🛠️ Getting Started
- Place your .pcap files in the working directory.
- Ensure Ollama is running if you want AI features.
- Run the script and follow the prompts.

DeltaPerf AI transforms raw packet data into meaningful insights with a blend of analytics and AI. Whether you're debugging network issues or conducting forensic analysis, this tool delivers clarity, speed, and intelligence.

Contributions and feedback are welcome!
