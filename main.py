from scapy.all import sniff, IP, TCP, UDP

# List untuk menyimpan alamat IP yang terdeteksi melakukan port scanning
detected_ips = []

# Fungsi callback untuk memproses paket yang tertangkap
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Deteksi port scanning (contoh: lebih dari 10 koneksi ke port dalam 1 detik)
        if TCP in packet and packet[TCP].flags == 2:  # Flag SYN
            if detected_ips.count(ip_src) >= 10:
                if ip_src not in detected_ips:
                    print(f"Port scanning detected from {ip_src}")
                    detected_ips.append(ip_src)

        # Periksa apakah paket adalah TCP atau UDP
        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            proto = "OTHER"
            src_port = "-"
            dst_port = "-"

        print(f"[{proto}] {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

# Menangkap paket (gunakan "iface" untuk menentukan interface jaringan)
sniff(prn=packet_callback, store=0)
