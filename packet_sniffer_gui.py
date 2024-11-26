import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox, filedialog
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import queue
from scapy.all import sniff, TCP, UDP, ICMP, ARP, IP, wrpcap


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Packet Sniffer")
        self.root.geometry("1200x900")
        self.root.configure(bg="#222831")

        # Display disclaimer on ethical use
        self.display_disclaimer()

        # GUI Styling
        self.configure_gui_style()

        # GUI Elements
        self.create_gui_layout()

        # Internal attributes
        self.packet_queue = queue.Queue()
        self.captured_packets = []
        self.sniffing_event = threading.Event()
        self.sniff_thread = None

        # Alert thresholds
        self.alert_thresholds = {
            'ICMP': 50,  # Alert if more than 50 ICMP packets are captured
            'RST': 10    # Alert if more than 10 TCP RST packets are detected
        }
        self.alert_counts = {'ICMP': 0, 'RST': 0}

    def display_disclaimer(self):
        """Show a popup disclaimer about ethical use."""
        messagebox.showinfo(
            "Disclaimer",
            "This tool is for educational purposes only. Ensure you have proper authorization before using this application."
        )

    def configure_gui_style(self):
        """Set up GUI styles for the application."""
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Custom.TFrame', background='#393e46')
        style.configure('Custom.TLabelframe', background='#00adb5', foreground='white', font=("Helvetica", 12, "bold"))
        style.configure('Custom.TButton', background='#00adb5', foreground='#eeeeee', font=("Helvetica", 10, "bold"))
        style.configure('Custom.TCheckbutton', background='#00adb5', foreground='#eeeeee')

    def create_gui_layout(self):
        """Create GUI layout."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10", style="Custom.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Status Label
        self.status_label = tk.Label(main_frame, text="Status: Idle", bg="#222831", fg="#00adb5", font=("Helvetica", 12, "bold"))
        self.status_label.pack(anchor="w", padx=10)

        # Network Interface selection
        self.create_interface_selection(main_frame)

        # Protocol filtering checkboxes
        self.create_protocol_filters(main_frame)

        # Control buttons
        self.create_buttons(main_frame)

        # Packet Details Output
        self.create_packet_output(main_frame)

        # Packet Visualization
        self.create_visualization(main_frame)

    def create_interface_selection(self, parent):
        """Create network interface selection UI."""
        interface_frame = ttk.LabelFrame(parent, text="Network Interface", padding="10", style="Custom.TLabelframe")
        interface_frame.pack(fill=tk.X, pady=5)
        self.interface_combo = ttk.Combobox(interface_frame, values=list(psutil.net_if_addrs().keys()), state="readonly", font=("Helvetica", 10))
        self.interface_combo.set("Select Interface")
        self.interface_combo.pack(fill=tk.X, padx=5, pady=5)
        self.add_tooltip(self.interface_combo, "Select a network interface for sniffing packets.")

    def create_protocol_filters(self, parent):
        """Create protocol filter checkboxes."""
        filter_frame = ttk.LabelFrame(parent, text="Protocol Filters", padding="10", style="Custom.TLabelframe")
        filter_frame.pack(fill=tk.X, pady=5)
        self.tcp_var = tk.BooleanVar()
        self.udp_var = tk.BooleanVar()
        self.http_var = tk.BooleanVar()
        self.https_var = tk.BooleanVar()
        self.icmp_var = tk.BooleanVar()
        self.arp_var = tk.BooleanVar()
        filters = [
            ("TCP", self.tcp_var),
            ("UDP", self.udp_var),
            ("HTTP", self.http_var),
            ("HTTPS", self.https_var),
            ("ICMP", self.icmp_var),
            ("ARP", self.arp_var),
        ]
        for text, var in filters:
            chk = ttk.Checkbutton(filter_frame, text=text, variable=var, style="Custom.TCheckbutton")
            chk.pack(side=tk.LEFT, padx=5)
            self.add_tooltip(chk, f"Filter packets by {text} protocol.")

    def create_buttons(self, parent):
        """Create control buttons."""
        button_frame = ttk.Frame(parent, padding="10", style="Custom.TFrame")
        button_frame.pack(fill=tk.X, pady=5)
        self.start_button = ttk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing_thread, style="Custom.TButton")
        self.stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state="disabled", style="Custom.TButton")
        self.save_button = ttk.Button(button_frame, text="Save Packets", command=self.save_packets, style="Custom.TButton")
        self.clear_button = ttk.Button(button_frame, text="Clear", command=self.clear_output, style="Custom.TButton")
        for btn in (self.start_button, self.stop_button, self.save_button, self.clear_button):
            btn.pack(side=tk.LEFT, padx=5)

    def create_packet_output(self, parent):
        """Create output area for packet details."""
        output_frame = ttk.LabelFrame(parent, text="Packet Details", padding="10", style="Custom.TLabelframe")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.output_text = scrolledtext.ScrolledText(output_frame, width=100, height=15, font=("Courier", 10), bg="#222831", fg="#eeeeee")
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_visualization(self, parent):
        """Create packet visualization chart."""
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'ICMP': 0, 'ARP': 0}
        self.fig, self.ax = plt.subplots()
        self.fig.patch.set_facecolor('#393e46')
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, pady=5)
        self.update_plot()

    def add_tooltip(self, widget, text):
        """Add a tooltip to a widget."""
        def show_tooltip(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25
            self.tooltip = tk.Toplevel()
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.geometry(f"+{x}+{y}")
            label = tk.Label(self.tooltip, text=text, bg="yellow", relief="solid", borderwidth=1, font=("Helvetica", 10))
            label.pack()

        def hide_tooltip(event):
            if hasattr(self, 'tooltip'):
                self.tooltip.destroy()

        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)

    def start_sniffing_thread(self):
        """Start sniffing packets in a separate thread."""
        interface = self.interface_combo.get()
        if interface == "Select Interface":
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.status_label.config(text="Status: Sniffing")
        self.sniffing_event.set()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.sniff_thread = threading.Thread(target=self.start_sniffing, args=(interface,))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        self.root.after(1000, self.process_packet_queue)

    def start_sniffing(self, interface):
        """Sniff packets on the specified interface."""
        try:
            sniff(
                iface=interface,
                prn=self.handle_packet,  # Call handle_packet for each captured packet
                store=False,
                stop_filter=lambda _: not self.sniffing_event.is_set()
            )
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {str(e)}\n")
            self.output_text.tag_config("error", foreground="red")

    def handle_packet(self, packet):
        """Add a captured packet to the queue."""
        self.packet_queue.put(packet)

    def process_packet_queue(self):
        """Process packets in the queue."""
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.captured_packets.append(packet)
            self.process_packet(packet)

        if self.sniffing_event.is_set():
            self.root.after(200, self.process_packet_queue)

    def process_packet(self, packet):
        """Process a single packet."""
        try:
            protocol = "Unknown"
            if IP in packet:
                if self.tcp_var.get() and TCP in packet:
                    self.protocol_counts['TCP'] += 1
                    protocol = "TCP"
                elif self.udp_var.get() and UDP in packet:
                    self.protocol_counts['UDP'] += 1
                    protocol = "UDP"
                elif self.http_var.get() and TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    self.protocol_counts['HTTP'] += 1
                    protocol = "HTTP"
                elif self.https_var.get() and TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                    self.protocol_counts['HTTPS'] += 1
                    protocol = "HTTPS"
                elif self.icmp_var.get() and ICMP in packet:
                    self.protocol_counts['ICMP'] += 1
                    protocol = "ICMP"
                elif self.arp_var.get() and ARP in packet:
                    self.protocol_counts['ARP'] += 1
                    protocol = "ARP"

                self.display_packet(packet, protocol)
            elif ARP in packet and self.arp_var.get():
                self.protocol_counts['ARP'] += 1
                protocol = "ARP"
                self.display_packet(packet, protocol)

            self.update_plot()
        except Exception as e:
            self.output_text.insert(tk.END, f"Error processing packet: {str(e)}\n", "error")
            self.output_text.tag_config("error", foreground="red")

    def display_packet(self, packet, protocol):
        """Display packet details in the output text area."""
        try:
            timestamp = packet.time
            src_ip = packet[IP].src if IP in packet else "N/A"
            dst_ip = packet[IP].dst if IP in packet else "N/A"
            length = len(packet)
            details = (
                f"Time: {timestamp:.6f}\n"
                f"Protocol: {protocol}\n"
                f"Source: {src_ip}\n"
                f"Destination: {dst_ip}\n"
                f"Length: {length} bytes\n"
                f"{'-'*50}\n"
            )
            self.output_text.insert(tk.END, details)
            self.output_text.see(tk.END)
        except Exception as e:
            self.output_text.insert(tk.END, f"Error displaying packet: {str(e)}\n", "error")
            self.output_text.tag_config("error", foreground="red")

    def update_plot(self):
        """Update the protocol visualization with unique colors."""
        self.ax.clear()
        protocols = list(self.protocol_counts.keys())
        counts = list(self.protocol_counts.values())

        # Assign unique colors for each protocol
        colors = ['#00adb5', '#ff5722', '#ffd369', '#9c27b0', '#3f51b5', '#8bc34a']

        # Create the bar chart
        bars = self.ax.bar(protocols, counts, color=colors[:len(protocols)])  # Use only the required colors

        # Set plot styling
        self.ax.set_title("Packet Count by Protocol", color="white", fontsize=14)
        self.ax.set_facecolor('#222831')
        self.ax.grid(color="#393e46", linestyle="--", linewidth=0.5)
        self.ax.tick_params(colors="white")

        # Add value labels on top of each bar
        for bar in bars:
            yval = bar.get_height()
            self.ax.text(bar.get_x() + bar.get_width() / 2, yval + 1, int(yval), ha='center', va='bottom', fontsize=10, color='white')

        # Redraw the canvas
        self.canvas.draw()

    def stop_sniffing(self):
        """Stop sniffing packets."""
        self.sniffing_event.clear()
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Status: Idle")

    def save_packets(self):
        """Save captured packets to a file."""
        if not self.captured_packets:
            messagebox.showwarning("Warning", "No packets to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            wrpcap(file_path, self.captured_packets)
            messagebox.showinfo("Info", f"Packets saved to {file_path}")

    def clear_output(self):
        """Clear the output area and reset visualization."""
        self.output_text.delete(1.0, tk.END)
        self.protocol_counts = {key: 0 for key in self.protocol_counts}
        self.captured_packets = []
        self.update_plot()


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
