# extract packet metadata from pcap files using tshark

import io
import os
import pandas as pd
import numpy as np
import subprocess
import sys
import re
import time
import argparse
from datetime import datetime
from multiprocessing import Pool
from functools import partial

# initialize pretty logging
from loguru import logger

# global variables
tshark_path = 'tshark'
data_path = os.path.join('data_merged_extracted', 'pcap')
output_path = os.path.join('data_merged_extracted', 'clean')
num_cores = 14

# function to extract packet metadata from pcap files using tshark
def extract_features(file):
    logger.info(f"Processing {file}", enqueue=True)
    
    # extract packet metadata from pcap files using tshark
    # build tshark arguments
    base_command = [tshark_path, '-r', file, '-T', 'fields', '-n', '-E', 'separator=/t', '-E', 'header=y']
    tshark_fields = [
        'frame.time_epoch', # timestamp of frame in seconds since epoch
        'frame.time_delta', # time delta from previous frame
        'frame.protocols', # protocols in frame
        'frame.len', # frame length
        'frame.encap_type', # frame encapsulation type
        
        'ip.src', # source ip address
        'ip.dst', # destination ip address
        
        'eth.type', # ethernet type (IPv4, IPv6, ARP, etc.)
        
        'tcp.len', # tcp length
        'tcp.seq', # tcp sequence number
        'tcp.ack', # tcp acknowledgement number
        'tcp.hdr_len', # tcp header length
        'tcp.flags', # tcp flags
        'tcp.urgent_pointer', # tcp urgent pointer
        
        'tcp.flags.res', # tcp reserved flag
        'tcp.flags.ae', # tcp accurate ecn flag
        'tcp.flags.cwr', # tcp congestion window reduced flag
        'tcp.flags.ece', # tcp ecn-echo flag
        'tcp.flags.urg', # tcp urgent flag
        'tcp.flags.ack', # tcp acknowledgement flag
        'tcp.flags.push', # tcp push flag
        'tcp.flags.reset', # tcp reset flag
        'tcp.flags.syn', # tcp syn flag
        'tcp.flags.fin', # tcp fin flag
    ]

    args = "-e " + " -e ".join(tshark_fields)
    command = " ".join(base_command) + " " + args

    # run tshark command
    try:
        result = subprocess.check_output(command, shell=True).decode('utf-8')
        # remove excess newlines and convert \r\n to \n
        result = result.replace('\r\n', '\n')
        # get first row
        first_row = result.split('\n')[0]
        # replace '.' with '_' in column names
        first_row = first_row.replace('.', '_')
        
        # set first row of result with new column names
        result = first_row + '\n' + result[len(first_row)+1:]
        
        filename = os.path.basename(file) + '.tsv'
        # save as tsv in output directory
        with open(os.path.join(output_path, filename), 'w', encoding='utf-8') as f:
            f.write(result)
    
        # print result
        logger.info(f"Successfully processed {file}", enqueue=True)
     
    except subprocess.CalledProcessError as e:
        logger.error(f"Error processing {file}: returned {e.returncode}", enqueue=True)
        return None

if __name__ == '__main__':
    # make output directory if it doesn't exist
    os.makedirs(output_path, exist_ok=True)

    # get list of pcap files
    pcap_files = [os.path.join(data_path, f) for f in os.listdir(data_path)]

    logger.info(f"Found {len(pcap_files)} pcap files", enqueue=True)

    # # limit number of files for testing
    # pcap_files = pcap_files[2:3]
    
    logger.info(f"Processing {len(pcap_files)} pcap files", enqueue=True)

    # extract features from pcap files
    with Pool(num_cores) as p:
        p.map(extract_features, pcap_files)

    # wait for all processes to finish
    p.close()