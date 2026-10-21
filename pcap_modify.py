from scapy.all import *
import sys

def modify_pcap(input_file, output_file,
                src_ip=None, dst_ip=None,
                src_port=None, dst_port=None,
                src_mac=None, dst_mac=None):
    
    packets = rdpcap(input_file)
    modified_packets = []
    
    for i, pkt in enumerate(packets):
        # 保存原始时间戳
        original_time = pkt.time if hasattr(pkt, 'time') else None
        original_sec = getattr(pkt, 'sec', None)
        original_usec = getattr(pkt, 'usec', None)
        
        # Copy packet
        new_pkt = pkt.copy()
        
        # Check if it's Linux cooked capture (SLL)
        is_sll = False
        
        # Determine if it's an SLL packet
        if hasattr(new_pkt, 'name') and new_pkt.name == 'Linux cooked capture':
            is_sll = True
        elif hasattr(new_pkt, 'type') and new_pkt.type == 113:  # Ethernet type for SLL
            is_sll = True
        elif 'SLL' in str(type(new_pkt)) or 'CookedLinux' in str(type(new_pkt)):
            is_sll = True
        
        # If it's an SLL packet, convert to Ethernet format
        if is_sll:
            try:
                # Create new Ethernet layer
                eth_layer = Ether()
                
                # Extract MAC address from SLL (if available)
                if hasattr(new_pkt, 'addr'):
                    try:
                        sll_addr = new_pkt.addr
                        if sll_addr and sll_addr != 0:
                            # Convert to hex and format as MAC address
                            mac_str = hex(sll_addr)[2:].zfill(12)
                            formatted_mac = ':'.join([mac_str[i:i+2] for i in range(0, 12, 2)])
                            eth_layer.src = formatted_mac
                    except:
                        pass
                
                # Apply user-specified MAC addresses (highest priority)
                if src_mac:
                    eth_layer.src = src_mac
                if dst_mac:
                    eth_layer.dst = dst_mac
                
                # Get SLL payload
                if new_pkt.payload:
                    # Build new packet: Ethernet layer + original SLL payload
                    new_pkt = eth_layer / new_pkt.payload
                else:
                    new_pkt = eth_layer
                    
            except Exception as e:
                print(f"Error converting SLL packet (packet {i+1}): {e}")
                new_pkt = new_pkt  # Keep original
        
        # For packets already in Ethernet format, directly modify MAC addresses
        elif Ether in new_pkt:
            if src_mac:
                new_pkt[Ether].src = src_mac
            if dst_mac:
                new_pkt[Ether].dst = dst_mac
        
        # Modify IP addresses (IP layer)
        if IP in new_pkt:
            if src_ip:
                new_pkt[IP].src = src_ip
            if dst_ip:
                new_pkt[IP].dst = dst_ip
            
            # Delete checksum for recalculation
            del new_pkt[IP].chksum
        
        # Modify IPv6 addresses
        elif IPv6 in new_pkt:
            if src_ip:
                new_pkt[IPv6].src = src_ip
            if dst_ip:
                new_pkt[IPv6].dst = dst_ip
        
        # Modify TCP ports
        if TCP in new_pkt:
            if src_port:
                new_pkt[TCP].sport = src_port
            if dst_port:
                new_pkt[TCP].dport = dst_port
            # Delete TCP checksum for recalculation
            if hasattr(new_pkt[TCP], 'chksum'):
                del new_pkt[TCP].chksum
        
        # Modify UDP ports
        elif UDP in new_pkt:
            if src_port:
                new_pkt[UDP].sport = src_port
            if dst_port:
                new_pkt[UDP].dport = dst_port
            # Delete UDP checksum for recalculation
            if hasattr(new_pkt[UDP], 'chksum'):
                del new_pkt[UDP].chksum
        
        # Force recalculation of all checksums
        try:
            # Rebuild packet from raw bytes to ensure checksum recalculation
            new_pkt = new_pkt.__class__(bytes(new_pkt))
        except:
            # Fallback method if above fails
            if IP in new_pkt:
                new_pkt[IP].chksum = None
            if TCP in new_pkt:
                new_pkt[TCP].chksum = None
            elif UDP in new_pkt:
                new_pkt[UDP].chksum = None
        
        # 恢复原始时间戳
        if original_time is not None:
            new_pkt.time = original_time
        
        # 对于PCAP格式，还需要设置sec和usec
        if hasattr(new_pkt, 'sec') and original_sec is not None:
            new_pkt.sec = original_sec
        if hasattr(new_pkt, 'usec') and original_usec is not None:
            new_pkt.usec = original_usec
        
        modified_packets.append(new_pkt)
        
        # Display progress
        if (i + 1) % 100 == 0:
            print(f"Processed {i+1}/{len(packets)} packets")
    
    # 使用PcapWriter保存，确保时间戳被保留
    print(f"\nSaving {len(modified_packets)} packets to {output_file}...")
    with PcapWriter(output_file, sync=True) as writer:
        for pkt in modified_packets:
            writer.write(pkt)
    
    print(f"\nSuccessfully processed {len(modified_packets)} packets, saved to {output_file}")

def detect_pcap_type(input_file):
    """Detect pcap file type"""
    packets = rdpcap(input_file)
    if len(packets) > 0:
        first_pkt = packets[0]
        print(f"Packet type detection:")
        print(f"  First packet type: {type(first_pkt)}")
        print(f"  Packet summary: {first_pkt.summary()}")
        
        # Check if it's SLL
        if hasattr(first_pkt, 'name'):
            print(f"  Packet name: {first_pkt.name}")
        if hasattr(first_pkt, 'type'):
            print(f"  Ethernet type: {first_pkt.type}")
        
        # List all layers
        print(f"  Packet layers: {first_pkt.layers()}")
        
        # Check first few packets
        sll_count = 0
        ether_count = 0
        for i, pkt in enumerate(packets[:10]):
            # Determine if it's an SLL packet
            if hasattr(pkt, 'name') and pkt.name == 'Linux cooked capture':
                sll_count += 1
            elif hasattr(pkt, 'type') and pkt.type == 113:  # Ethernet type for SLL
                sll_count += 1
            elif 'SLL' in str(type(pkt)) or 'CookedLinux' in str(type(pkt)):
                sll_count += 1
            elif Ether in pkt:
                ether_count += 1
        
        print(f"  First 10 packets: sll packets num={sll_count}, ethernet packets num={ether_count}")
        return sll_count > 0
    return False

if __name__ == '__main__':
    # First detect file type
    print("Detecting input file type...")
    is_sll_file = detect_pcap_type("in.pcap")
    
    if is_sll_file:
        print("Detected Linux cooked capture (SLL) format, will automatically convert to Ethernet format")
    else:
        print("Detected standard Ethernet format")
    
    # Example usage: convert format and modify content
    modify_pcap(
        input_file="in.pcap",
        output_file="out.pcap",
        src_ip="10.10.40.71",
        dst_ip="10.10.40.121",
        src_port=7777,
        dst_port=8888,
        src_mac="00:E0:70:ED:E9:F7",
        dst_mac="a4:bf:01:6e:af:9b"
    )