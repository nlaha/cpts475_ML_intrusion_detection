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

NUM_CORES = 20

########################
# Source dataset paths #
########################
SOURCE_DATA_DIR = os.path.join("source_data", "Original Network Traffic and Log data")


#########################
# Mappings and Features #
#########################

# Attacker	Victim	Attack Name	Date	Attack Start Time	Attack Finish Time
# 172.31.70.4
# (Valid IP:18.221.219.4)	172.31.69.25
# (Valid IP:18.217.21.148)	FTP-BruteForce	Wed-14-02-2018	10:32	12:09
# 172.31.70.6
# (Valid IP:13.58.98.64)	18.217.21.148- 172.31.69.25	SSH-Bruteforce	Wed-14-02-2018	14:01	15:31
# 172.31.70.46
# (Valid IP:18.219.211.138)	18.217.21.148- 172.31.69.25	DoS-GoldenEye	Thurs-15-02-2018	9:26	10:09
# 172.31.70.8
# (Vazlid IP:18.217.165.70)	18.217.21.148- 172.31.69.25	DoS-Slowloris	Thurs-15-02-2018	10:59	11:40
# 172.31.70.23
# (Valid IP: 13.59.126.31)	18.217.21.148- 172.31.69.25	DoS-SlowHTTPTest	Fri-16-02-2018	10:12	11:08
# 172.31.70.16
# (Valid IP:18.219.193.20)	18.217.21.148- 172.31.69.25	DoS-Hulk	Fri-16-02-2018	13:45	14:19
# 18.218.115.60
# 18.219.9.1
# 18.219.32.43
# 18.218.55.126
# 52.14.136.135
# 18.219.5.43
# 18.216.200.189
# 18.218.229.235
# 18.218.11.51
# 18.216.24.42	18.217.21.148- 172.31.69.25	DDoS attacks-LOIC-HTTP	Tues-20-02-2018	10:12	11:17
# 18.218.115.60
# 18.219.9.1
# 18.219.32.43
# 18.218.55.126
# 52.14.136.135
# 18.219.5.43
# 18.216.200.189
# 18.218.229.235
# 18.218.11.51
# 18.216.24.42	18.217.21.148- 172.31.69.25	DDoS-LOIC-UDP	Tues-20-02-2018	13:13	13:32
# 18.218.115.60
# 18.219.9.1
# 18.219.32.43
# 18.218.55.126
# 52.14.136.135
# 18.219.5.43
# 18.216.200.189
# 18.218.229.235
# 18.218.11.51
# 18.216.24.42	18.218.83.150- 172.31.69.28	DDOS-LOIC-UDP	Wed-21-02-2018	10:09	10:43
# 18.218.115.60
# 18.219.9.1
# 18.219.32.43
# 18.218.55.126
# 52.14.136.135
# 18.219.5.43
# 18.216.200.189
# 18.218.229.235
# 18.218.11.51
# 18.216.24.42	18.218.83.150- 172.31.69.28	DDOS-HOIC	Wed-21-02-2018	14:05	15:05
# 18.218.115.60	18.218.83.150- 172.31.69.28	Brute Force -Web	Thurs-22-02-2018	10:17	11:24
# 18.218.115.60	18.218.83.150- 172.31.69.28	Brute Force -XSS	Thurs-22-02-2018	13:50	14:29
# 18.218.115.60	18.218.83.150- 172.31.69.28	SQL Injection	Thurs-22-02-2018	16:15	16:29
# 18.218.115.60	18.218.83.150- 172.31.69.28	Brute Force -Web	Fri-23-02-2018	10:03	11:03
# 18.218.115.60	18.218.83.150- 172.31.69.28	Brute Force -XSS	Fri-23-02-2018	13:00	14:10
# 18.218.115.60	18.218.83.150- 172.31.69.28	SQL Injection	Fri-23-02-2018	15:05	15:18
# 13.58.225.34	18.221.148.137-172.31.69.24	Infiltration	Wed-28-02-2018	10:50	12:05
# 13.58.225.34	18.221.148.137-172.31.69.24	Infiltration	Wed-28-02-2018	13:42	14:40
# 13.58.225.34	18.216.254.154-172.31.69.13	Infiltration	Thursday-01-03-2018	9:57	10:55
# 13.58.225.34	18.216.254.154-172.31.69.13	Infiltration	Thursday-01-03-2018	14:00	15:37
# 13.58.225.34	18.216.254.154-172.31.69.13	Infiltration	Thursday-01-03-2018	14:00	15:37
# 18.219.211.138	18.217.218.111-172.31.69.23
# 18.222.10.237-172.31.69.17
# 18.222.86.193-172.31.69.14
# 18.222.62.221-172.31.69.12
# 13.59.9.106-172.31.69.10
# 18.222.102.2-172.31.69.8
# 18.219.212.0-172.31.69.6
# 18.216.105.13-172.31.69.26
# 18.219.163.126-172.31.69.29
# 18.216.164.12-172.31.69.30	Bot	Friday-02-03-2018	10:11	11:34
# 18.219.211.138	18.217.218.111-172.31.69.23
# 18.222.10.237-172.31.69.17
# 18.222.86.193-172.31.69.14
# 18.222.62.221-172.31.69.12
# 13.59.9.106-172.31.69.10
# 18.222.102.2-172.31.69.8
# 18.219.212.0-172.31.69.6
# 18.216.105.13-172.31.69.26
# 18.219.163.126-172.31.69.29
# 18.216.164.12-172.31.69.30	Bot	Friday-02-03-2018	14:24	15:55

ATTACK_TIMES = [
    ("Wednesday-14-02-2018", "10:32", "12:09", "FTP-BruteForce"),
    ("Wednesday-14-02-2018", "14:01", "15:31", "SSH-Bruteforce"),
    ("Thursday-15-02-2018", "9:26", "10:09", "DoS-GoldenEye"),
    ("Thursday-15-02-2018", "10:59", "11:40", "DoS-Slowloris"),
    ("Friday-16-02-2018", "10:12", "11:08", "DoS-SlowHTTPTest"),
    ("Friday-16-02-2018", "13:45", "14:19", "DoS-Hulk"),
    ("Tuesday-20-02-2018", "10:12", "11:17", "DDoS attacks-LOIC-HTTP"),
    ("Tuesday-20-02-2018", "13:13", "13:32", "DDoS-LOIC-UDP"),
    ("Wednesday-21-02-2018", "10:09", "10:43", "DDOS-LOIC-UDP"),
    ("Wednesday-21-02-2018", "14:05", "15:05", "DDOS-HOIC"),
    ("Thursday-22-02-2018", "10:17", "11:24", "Brute Force -Web"),
    ("Thursday-22-02-2018", "13:50", "14:29", "Brute Force -XSS"),
    ("Thursday-22-02-2018", "16:15", "16:29", "SQL Injection"),
    ("Friday-23-02-2018", "10:03", "11:03", "Brute Force -Web"),
    ("Friday-23-02-2018", "13:00", "14:10", "Brute Force -XSS"),
    ("Friday-23-02-2018", "15:05", "15:18", "SQL Injection"),
    ("Wednesday-28-02-2018", "10:50", "12:05", "Infiltration"),
    ("Wednesday-28-02-2018", "13:42", "14:40", "Infiltration"),
    ("Thursday-01-03-2018", "9:57", "10:55", "Infiltration"),
    ("Thursday-01-03-2018", "14:00", "15:37", "Infiltration"),
    ("Thursday-01-03-2018", "14:00", "15:37", "Infiltration"),
    ("Friday-02-03-2018", "10:11", "11:34", "Bot"),
    ("Friday-02-03-2018", "14:24", "15:55", "Bot"),
]

ATTACKER_IPS = [
    "18.221.219.4",
    "13.58.98.64",
    "18.219.211.138",
    "18.217.165.70",
    "13.59.126.31",
    "18.219.193.20",
    "18.218.115.60",
    "18.219.9.1",
    "18.219.32.43",
    "18.218.55.126",
    "52.14.136.135",
    "18.219.5.43",
    "18.216.200.189",
    "18.218.229.235",
    "18.218.11.51",
    "18.216.24.42",
    "18.218.83.150",
    "13.58.225.34",
    "18.219.211.138",
    "18.217.218.111",
    "18.222.10.237",
    "18.222.86.193",
    "18.222.62.221",
    "13.59.9.106",
    "18.222.102.2",
    "18.219.212.0",
    "18.216.105.13",
    "18.219.163.126",
    "18.216.164.12"
]

# Mapping of data subsets to attack types
DATA_SUBSET_MAPPING = {
    "Friday-02-03-2018": "bots",
    "Thursday-01-03-2018": "infiltration",
    "Wednesday-28-02-2018": "infiltration",
    "Friday-23-02-2018": "web_attacks",  # SQL Injection, Brute Force, XSS, etc.
    "Thursday-22-02-2018": "web_attacks",  # SQL Injection, Brute Force, XSS, etc.
    "Wednesday-21-02-2018": "ddos",
    "Tuesday-20-02-2018": "ddos",
    "Friday-16-02-2018": "dos",
    "Thursday-15-02-2018": "dos",
    "Wednesday-14-02-2018": "auth_brute_force",  # SSH, FTP, etc.
    # will be 'benign' if not in the above list
}

# Mapping of attack types to integer labels
ATTACK_TYPE_MAPPING = {
    'Benign': 0,
    'FTP-BruteForce': 1,
    'SSH-Bruteforce': 2,
    'DoS-GoldenEye': 3,
    'DoS-Slowloris': 4,
    'DoS-SlowHTTPTest': 5,
    'DoS-Hulk': 6,
    'DDoS attacks-LOIC-HTTP': 7,
    'DDoS-LOIC-UDP': 8,
    'DDOS-LOIC-UDP': 9,
    'DDOS-HOIC': 10,
    'Brute Force -Web': 11,
    'Brute Force -XSS': 12,
    'SQL Injection': 13,
    'Infiltration': 14,
    'Bot': 15,
}

TSHARK_FIELDS = [
    "frame.time_epoch",     # timestamp of frame in seconds since epoch
    "frame.time_delta",     # time delta from previous frame
    "frame.protocols",      # protocols in frame
    "frame.len",            # frame length
    "frame.encap_type",     # frame encapsulation type
    "ip.src",               # source ip address
    "ip.dst",               # destination ip address
    "ip.proto",             # ip protocol (tcp, udp, etc.)
    "ip.flags.df",          # ip do not fragment flag
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
    "tcp.time_relative",    # tcp time relative (time since first packet in tcp stream)
]

TSHARK_DB_COLS = """
    frame_time_epoch DOUBLE,
    frame_time_delta DOUBLE,
    frame_protocols VARCHAR,
    frame_len BIGINT,
    frame_encap_type INT,
    ip_src VARCHAR,
    ip_dst VARCHAR,
    ip_proto VARCHAR,
    ip_flags_df VARCHAR,
    eth_type VARCHAR,
    tcp_len BIGINT,
    tcp_seq BIGINT,
    tcp_ack BIGINT,
    tcp_hdr_len INT,
    tcp_flags INT,
    tcp_urgent_pointer INT,
    tcp_flags_res BOOLEAN,
    tcp_flags_ae BOOLEAN,
    tcp_flags_cwr BOOLEAN,
    tcp_flags_ece BOOLEAN,
    tcp_flags_urg BOOLEAN,
    tcp_flags_ack BOOLEAN,
    tcp_flags_push BOOLEAN,
    tcp_flags_reset BOOLEAN,
    tcp_flags_syn BOOLEAN,
    tcp_flags_fin BOOLEAN,
    tcp_time_relative DOUBLE
"""