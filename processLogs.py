import os
import argparse

# this function is to read the lookup table and process the flow logs
def read_lookup_table(filename):
    lookup_table = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(',')
                if len(parts) != 3:
                    print(f"Invalid format for entry found: {line}")
                    continue
                port, protocol, tag = map(str.strip, parts)
                if port == "dstport":
                    continue
                try:
                    port_int = int(port)
                except ValueError:
                    print(f"Error converting port to integer: {port}, entry is {line}")
                    continue
                lookup_table.setdefault(port_int, {})[protocol.lower()] = tag.lower()
    except IOError as e:
        return None, e
    return lookup_table, None

# this function is to process the flow logs
def process_flow_logs(filename, lookup_table, log_format=None):
    tag_counts = {}
    port_and_protocol_counts = {}
    try:
        destination_port_index = 6 # default index for destination port
        protocol_index = 7 # default index for protocol
        if log_format:
            parts = log_format.split()
            destination_port_index = parts.index("dstport")
            protocol_index = parts.index("protocol")
        with open(filename, 'r') as file:
            min_parts_len = max(destination_port_index, protocol_index) + 1
            for line in file:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < min_parts_len:
                    print(f"Invalid log found has less entries than expected: {line}")
                    continue

                try:
                    dst_port = int(parts[destination_port_index])
                except ValueError:
                    print(f"Invalid port Number: {parts[destination_port_index]} in the log flow entry found")
                    continue

                protocol_number = parts[protocol_index]
                protocol = protocol_to_number(protocol_number)
                tag = lookup_table.get(dst_port, {}).get(protocol.lower(), "Untagged")
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

                port_and_protocol_counts.setdefault(dst_port, {})
                port_and_protocol_counts[dst_port][protocol] = port_and_protocol_counts[dst_port].get(protocol, 0) + 1
    except IOError as e:
        return None, None, e
    return tag_counts, port_and_protocol_counts, None

def interactive_mode():
    print("Welcome to interactive mode!")
    log_format = input("Are you using the default log format? (yes/no): ").lower()
    lookup_table_filename = "lookup_table.txt" # default lookup table filename
    log_files_filename = "log_files.txt" # default log files filename
    custom_format = None
    if log_format == 'no':
        print("Please enter the custom log format.")
        print("Use space-separated field names. Include 'dst_port' and 'protocol' in your format.")
        print("Example: timestamp src_ip dst_ip dst_port src_port protocol")
        custom_format = input("Enter your custom format: ")
        parts = custom_format.split()
        while "dstport" not in parts or "protocol" not in parts:
            print("Custom log format must include 'dstport' and 'protocol' please try again.")
            custom_format = input("Enter your custom format: ")
            parts = custom_format.split()

    lookup_table_filename = input("Enter the lookup table filename: ")
    while not os.path.exists(lookup_table_filename):
        print(f"Lookup table file {lookup_table_filename} not found please enter a valid file.")
        lookup_table_filename = input("Enter the lookup table filename: ")

    log_files_filename = input("Enter the log files filename: ")
    while not os.path.exists(log_files_filename):
        print(f"Log files file {log_files_filename} not found please enter a valid file.")
        log_files_filename = input("Enter the log files filename: ")
            
    return custom_format, lookup_table_filename, log_files_filename
        
def main():
    parser = argparse.ArgumentParser(description="Process network logs")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    args = parser.parse_args()
    log_format = None
    lookup_table_filename = "lookup_table.txt"
    log_files_filename = "log_files.txt"
    if args.interactive:
        log_format, lookup_table_filename, log_files_filename = interactive_mode()

    lookup_table, err = read_lookup_table(lookup_table_filename)
    if err:
        print(f"Error reading lookup table: {err}")
        return

    tag_counts, port_protocol_counts, err = process_flow_logs(log_files_filename, lookup_table, log_format)
    if err:
        print(f"Error processing the log files: {err}")
        return

    try:
        with open("tag_counts.txt", 'w') as file:
            for key, count in tag_counts.items():
                file.write(f"{key},{count}\n")

        with open("port_protocol_counts.txt", 'w') as file:
            for port, protocol_map in port_protocol_counts.items():
                for protocol, count in protocol_map.items():
                    file.write(f"{port},{protocol},{count}\n")
    except IOError as e:
        print(f"Error writing to result files: {e}")

def protocol_to_number(protocol):
    protocol_to_number_dict = {
        "0": "HOPOPT",
        "1": "ICMP",
        "2": "IGMP",
        "3": "GGP",
        "4": "IPv4",
        "5": "ST",
        "6": "TCP",
        "7": "CBT",
        "8": "EGP",
        "9": "IGP",
        "10": "BBN-RCC-MON",
        "11": "NVP-II",
        "12": "PUP",
        "13": "ARGUS",
        "14": "EMCON",
        "15": "XNET",
        "16": "CHAOS",
        "17": "UDP",
        "18": "MUX",
        "19": "DCN-MEAS",
        "20": "HMP",
        "21": "PRM",
        "22": "XNS-IDP",
        "23": "TRUNK-1",
        "24": "TRUNK-2",
        "25": "LEAF-1",
        "26": "LEAF-2",
        "27": "RDP",
        "28": "IRTP",
        "29": "ISO-TP4",
        "30": "NETBLT",
        "31": "MFE-NSP",
        "32": "MERIT-INP",
        "33": "DCCP",
        "34": "3PC",
        "35": "IDPR",
        "36": "XTP",
        "37": "DDP",
        "38": "IDPR-CMTP",
        "39": "TP++",
        "40": "IL",
        "41": "IPv6",
        "42": "SDRP",
        "43": "IPv6-Route",
        "44": "IPv6-Frag",
        "45": "IDRP",
        "46": "RSVP",
        "47": "GRE",
        "48": "DSR",
        "49": "BNA",
        "50": "ESP",
        "51": "AH",
        "52": "I-NLSP",
        "53": "SWIPE",
        "54": "NARP",
        "55": "Min-IPv4",
        "56": "TLSP",
        "57": "SKIP",
        "58": "IPv6-ICMP",
        "59": "IPv6-NoNxt",
        "60": "IPv6-Opts",
        "62": "CFTP",
        "64": "SAT-EXPAK",
        "65": "KRYPTOLAN",
        "66": "RVD",
        "67": "IPPC",
        "69": "SAT-MON",
        "70": "VISA",
        "71": "IPCV",
        "72": "CPNX",
        "73": "CPHB",
        "74": "WSN",
        "75": "PVP",
        "76": "BR-SAT-MON",
        "77": "SUN-ND",
        "78": "WB-MON",
        "79": "WB-EXPAK",
        "80": "ISO-IP",
        "81": "VMTP",
        "82": "SECURE-VMTP",
        "83": "VINES",
        "84": "IPTM",
        "85": "NSFNET-IGP",
        "86": "DGP",
        "87": "TCF",
        "88": "EIGRP",
        "89": "OSPFIGP",
        "90": "Sprite-RPC",
        "91": "LARP",
        "92": "MTP",
        "93": "AX.25",
        "94": "IPIP",
        "95": "MICP",
        "96": "SCC-SP",
        "97": "ETHERIP",
        "98": "ENCAP",
        "100": "GMTP",
        "101": "IFMP",
        "102": "PNNI",
        "103": "PIM",
        "104": "ARIS",
        "105": "SCPS",
        "106": "QNX",
        "107": "A/N",
        "108": "IPComp",
        "109": "SNP",
        "110": "Compaq-Peer",
        "111": "IPX-in-IP",
        "112": "VRRP",
        "113": "PGM",
        "115": "L2TP",
        "116": "DDX",
        "117": "IATP",
        "118": "STP",
        "119": "SRP",
        "120": "UTI",
        "121": "SMP",
        "122": "SM",
        "123": "PTP",
        "124": "ISIS over IPv4",
        "125": "FIRE",
        "126": "CRTP",
        "127": "CRUDP",
        "128": "SSCOPMCE",
        "129": "IPLT",
        "130": "SPS",
        "131": "PIPE",
        "132": "SCTP",
        "133": "FC",
        "134": "RSVP-E2E-IGNORE",
        "135": "Mobility Header",
        "136": "UDPLite",
        "137": "MPLS-in-IP",
        "138": "manet",
        "139": "HIP",
        "140": "Shim6",
        "141": "WESP",
        "142": "ROHC",
        "143": "Ethernet",
        "144": "AGGFRAG",
        "145": "NSH"
    }
    return protocol_to_number_dict.get(protocol, "unknown").lower()
if __name__ == "__main__":
    main()
    print("Process completed successfully!, the results are saved in tag_counts.txt and port_protocol_counts.txt")