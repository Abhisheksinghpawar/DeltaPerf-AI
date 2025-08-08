import os
import pyshark
from tabulate import tabulate
from colorama import Fore, Style, init
import requests
import json
from datetime import datetime

#initialize colorama
init(autoreset=True)

# DeltaPerf AI Banner
print(Fore.BLUE + "=" * 70)
print(Fore.MAGENTA + Style.BRIGHT + "\n🚀 Welcome to DeltaPerf AI")
print(Fore.WHITE + "🔍 Analyze. Detect. Summarize.\n")
print(Fore.BLUE + "=" * 70 + "\n")

print(Fore.WHITE + "Color Legend:\n")

print(
    Fore.WHITE + "Legend: " +
    Fore.RED + "🔴 >10s  " +
    Fore.YELLOW + "🟡 >1s  " +
    Fore.GREEN + "🟢 ≤1s  " +
    Fore.BLUE + "🔵 TCP  " +
    Fore.MAGENTA + "🟣 UDP  " +
    Fore.WHITE + "⚪ Other"
)

# Directory containing capturing files
capture_dir = "./" # change this to your capture directory

# Find all .pcap and .pcapng files in the directory
capture_files = []
for root, dirs, files in os.walk(capture_dir):
    for file in files:
        if file.endswith(".pcap") or file.endswith(".pcapng"):
            full_path = os.path.join(root, file)
            capture_files.append(full_path)
            
#Display available capture files
print(Fore.WHITE + f"\n📁 Available Capture Files: {len(capture_files)}\n")

#Ollama Summary Function
def generate_ollama_summary(events):
    event_lines = []
    for e in events:
        event_lines.append(f"{e['timestamp']} - {e['protocol']} | Latency: {e['delta']}s | Source: {e['src']}s | Destination: {e['dst']}")
        
        prompt = (
        "You are a network performance analysis expert. Analyze the following events and provide a summary:\n\n"
        "Focus on the following key points:\n"
        "- Latency patterns (High, Low, or Normal)\n"
        "Protocol distribution and behavior\n"
        "Any anomalies or unusual patterns\n"
        "Network Events:\n"
        "\n".join(event_lines) +
        "\n\nProvide your analysis in a concise format.\n"
    )
    
    response = requests.post(
        "http://127.0.0.1:11434/api/generate",
        headers={"Content-Type": "application/json"},
        json={"prompt": prompt, "model": model_used},
    )
    
    if response.status_code == 200:
        #result = response.json()
        #return result.get("response", "No response from model.")

        raw_text = response.text

        # If Ollama returns multiple JSON objects separated by newlines
        json_objects = [json.loads(line) for line in raw_text.strip().split('\n') if line.strip()]

        # Combine all 'response' fields if streaming
        combined_response = ''.join(obj.get("response", "") for obj in json_objects)

        return combined_response if combined_response else "No response from model."
    
    else:
        print(Fore.RED + "Error generating summary:", response.status_code, response.text)
        return "Error generating summary."
    
def is_ollama_available():
    try:
        response = requests.get("http://127.0.0.1:11434/")
        return response.status_code == 200
    except requests.ConnectionError:
        return False

#Summary Accumulation
total_files = 0
total_packets = 0
total_delta_sum = 0
total_delta_count = 0
total_high_delta_events = 0
ollama_events = []

# Process each capture file
for file_name in capture_files:
    print(Fore.BLUE + "=" * 70)
    print(Fore.BLUE + f"Processing Capture File: {file_name}")
    print(Fore.BLUE + "=" * 70 + "\n")
    
    file_path = os.path.join(capture_dir, file_name)
    
    try:
        capture = pyshark.FileCapture(file_path, use_json=True)
        packets_with_delta = []
        extreme_delta_count = 0
        high_delta_count = 0
        
        for packet in capture:
            try:
                delta = float(packet.frame_info.time_delta)
                packets_with_delta.append((delta,packet))
                total_delta_sum += delta
                total_delta_count += 1
                if delta > 1.0:
                    high_delta_count += 1
                    total_high_delta_events += 1
                if delta > 10.0:
                    extreme_delta_count += 1
            except AttributeError:
                continue
        capture.close()
        
        total_files += 1
        total_packets += len(packets_with_delta) +1
        
        if extreme_delta_count > 0:
            print(Fore.RED + f"🔥 Extreme Latency Events (>10s): {extreme_delta_count}\n")
        else:
            print(Fore.GREEN + "✅ No Extreme Latency Events (>10s) Found\n")
            
        packets_with_delta.sort(key=lambda x: x[0], reverse=True)
        
        table_data = []
        for i, (delta, packet) in enumerate(packets_with_delta[:5], start=1):
            try:
                timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                number = packet.number
                raw_protocol = packet.highest_layer.upper()

                if raw_protocol == "TCP":
                    protocol = Fore.BLUE + raw_protocol+ Style.RESET_ALL
                    
                elif raw_protocol == "UDP":
                    protocol = Fore.MAGENTA + raw_protocol + Style.RESET_ALL

                else:
                    protocol = Fore.WHITE + raw_protocol +Style.RESET_ALL

                
                length = packet.length

                src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'

                if hasattr(packet, 'tcp'):
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                
                elif hasattr(packet, 'udp'):
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport
                
                else:
                    src_port = dst_port = 'N/A'

                if delta > 10.0:
                    delta_str = Fore.RED + f"{delta: .6f}s" + Style.RESET_ALL

                elif delta > 1.0:
                    delta_str = Fore. YELLOW + f"{delta:.6f}s" + Style.RESET_ALL
                
                else:
                    delta_str = Fore.GREEN + f"{delta: .6f}s" + Style.RESET_ALL

                table_data.append([
                i,
                delta_str,
                number,
                timestamp,
                protocol,
                length,
                src_ip,
                src_port,
                dst_ip,
                dst_port
                ])
                
                # Add to ollama event list
                ollama_events.append({
                "timestamp": timestamp,
                "protocol": raw_protocol,
                "delta": delta,
                "src": src_ip,
                "dst": dst_ip   
                })
            
            except Exception:
                table_data.append([i, "Error", "-", "-","-", "-", "-", "-", "-", "-"])

        headers = [
        "Rank",
        "Delta Time",
        "Frame #",
        "Timestamp",
        "Protocol",
        "Length (bytes)",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port"
        ]
    
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print("\n")

    except Exception as e:
        print(Fore.RED + f"Error processing file {file_name}: {e}\n")

#Final Summary Dashboard

avg_delta = total_delta_sum / total_delta_count if total_delta_count > 0 else 0

summary_table = [
    ["📁 Total Capture Files Processed", str(total_files)],
    ["📦 Total Packets Analyzed", str(total_packets)],
    ["🔥 Latency Events (>1s)", str(total_high_delta_events)],
    ["🧮 Average Delta Time (s)", f"{avg_delta:.6f}"],
]
print(Fore.BLUE + "=" * 70)
print(Fore.BLUE + "📊 Final Summary Dashboard")
print(tabulate(summary_table, headers=["Metric", "Value"], tablefmt="grid", stralign="left", numalign="right"))
print(Fore.BLUE + "=" * 70 + "\n")

# DeltaPerf AI Ollama Summary

if is_ollama_available():
    user_input = input (Fore.CYAN + "💬 Would you like to generate an AI summary using ollama? (y/n): ").strip().lower()

    if user_input == 'y':
        model_used = "tinyllama:1.1b"
        summary_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        event_count = len(ollama_events)

        print (Fore.BLUE+ "\n🧠 DeltaPerf AI - ollama Summary")
        print (Fore.WHITE + f"🤖 Model: {model_used}")
        print (Fore.WHITE + f"🕒 Generated: {summary_time}")
        print (Fore.WHITE + f"📊 Events Analyzed: {event_count}\n")

        #Basic Summary
        basic_prompt = (
            "Summarize the following network events. Highlight any performance issues or notable paterns:\n\n"
        )
        ollama_output = generate_ollama_summary(ollama_events)
        print (Fore.WHITE + ollama_output + "\n")

        #Prompt for deeper insights
        deeper_input = input (Fore.CYAN+ "Do you want to get more insights using AI-powered anomaly detection? (y/n): ").strip().lower()

        if deeper_input == 'y':
            anomaly_prompt = (
                "Analyze the following network events for anomalies."
                "Look for unusual latency, retransmissions, or suspicious behavior"
                "Provide Actionable suggestions:\n\n"
                + json.dumps(ollama_events, indent=2)
            )
            
            anomaly_output = generate_ollama_summary(ollama_events)
            
            print(Fore.MAGENTA + "\n🧠 AI-Powered Anomaly Detection Summary:")
            print(Fore.WHITE + f"🤖 Model: {model_used}")
            print(Fore.WHITE + f"🕒 Generated: {datetime.now().strftime('%Y-%a-%d %H:%M:%S')}")
            print(Fore.WHITE + f"📊 Events Analyzed: {event_count}\n")
            print(Fore.WHITE + anomaly_output + "\n")
        else:
            print (Fore.YELLOW + "⚠️ Anomaly detection skipped by user. \n")
    else:
        print (Fore.YELLOW + "⚠️ A ollama summary and anomaly detection skipped by skipped by user \n")

else:
    print(Fore.RED + "❌ ollama is not running. Please start ollama server to use AI features.\n")















        