import os

# Path to tshark executable
TSHARK_PATH = "tshark"

# Path to the 7Zip executable
SEVENZIP_PATH = "7z"

# Path to the directory that will hold all the processed data
PROCESSED_DATA_DIR = "data"

# Path to the directory that will hold the extracted pcap files
PCAP_DATA_PATH = os.path.join(PROCESSED_DATA_DIR, "pcap")

# Path to the directory that will hold the packet metadata files
META_DATA_PATH = os.path.join(PROCESSED_DATA_DIR, "meta")

# Path to the duckdb database file
DUCKDB_PATH = os.path.join(PROCESSED_DATA_DIR, "pcap_metadata.duckdb")

NUM_CORES = 14

########################
# Source dataset paths #
########################
SOURCE_DATA_DIR = os.path.join("source_data", "Original Network Traffic and Log data")


#########################
# Mappings and Features #
#########################

# Mapping of data subsets to attack types
DATA_SUBSET_MAPPING = {
    "Friday-02-03-2018": "bots",
    "Thursday-01-03-2018": "infiltration",
    "Wed-28-02-2018": "infiltration",
    "Fri-23-02-2018": "web_attacks",  # SQL Injection, Brute Force, XSS, etc.
    "Thurs-22-02-2018": "web_attacks",  # SQL Injection, Brute Force, XSS, etc.
    "Wed-21-02-2018": "ddos",
    "Tues-20-02-2018": "ddos",
    "Fri-16-02-2018": "dos",
    "Thurs-15-02-2018": "dos",
    "Wed-14-02-2018": "auth_brute_force",  # SSH, FTP, etc.
    # will be 'benign' if not in the above list
}

# Mapping of attack types to integer labels
ATTACK_TYPE_MAPPING = {
    "benign": 0,
    "bots": 1,
    "infiltration": 2,
    "web_attacks": 3,
    "ddos": 4,
    "dos": 5,
    "auth_brute_force": 6,
}

TSHARK_FIELDS = [
    "frame.time_epoch",     # timestamp of frame in seconds since epoch
    "frame.time_delta",     # time delta from previous frame
    "frame.protocols",      # protocols in frame
    "frame.len",            # frame length
    "frame.encap_type",     # frame encapsulation type
    "ip.src",               # source ip address
    "ip.dst",               # destination ip address
    "eth.type",             # ethernet type (IPv4, IPv6, ARP, etc.)
    "tcp.len",              # tcp length
    "tcp.seq",              # tcp sequence number
    "tcp.ack",              # tcp acknowledgement number
    "tcp.hdr_len",          # tcp header length
    "tcp.flags",            # tcp flags
    "tcp.urgent_pointer",   # tcp urgent pointer
    "tcp.flags.res",        # tcp reserved flag
    "tcp.flags.ae",         # tcp accurate ecn flag
    "tcp.flags.cwr",        # tcp congestion window reduced flag
    "tcp.flags.ece",        # tcp ecn-echo flag
    "tcp.flags.urg",        # tcp urgent flag
    "tcp.flags.ack",        # tcp acknowledgement flag
    "tcp.flags.push",       # tcp push flag
    "tcp.flags.reset",      # tcp reset flag
    "tcp.flags.syn",        # tcp syn flag
    "tcp.flags.fin",        # tcp fin flag
]
