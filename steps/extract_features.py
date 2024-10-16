# extract packet metadata from pcap files using tshark

import os
import subprocess
from multiprocessing import Pool

# initialize pretty logging
from loguru import logger

from config import TSHARK_PATH, META_DATA_PATH, TSHARK_FIELDS, NUM_CORES, PCAP_DATA_PATH

# function to extract packet metadata from pcap files using tshark
def extract_features(file):
    """
        Extract packet metadata from pcap file using tshark.
    """
    
    logger.info(f"Processing {file}", enqueue=True)
    
    # extract packet metadata from pcap files using tshark
    # build tshark arguments
    base_command = [TSHARK_PATH, '-r', file, '-T', 'fields', '-n', '-E', 'separator=/t', '-E', 'header=y']

    args = "-e " + " -e ".join(TSHARK_FIELDS)
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
        
        # output path is similar to the input path but with the META_DATA_PATH instead of PCAP_DATA_PATH
        dirname = os.path.dirname(file).replace(PCAP_DATA_PATH, META_DATA_PATH)
        filename = os.path.basename(file) + '.tsv'
        path = os.path.join(dirname, filename)
        # save as tsv in output directory
        with open(path, 'w', encoding='utf-8') as f:
            f.write(result)
    
        # print result
        logger.info(f"Successfully processed {file}", enqueue=True)
     
    except subprocess.CalledProcessError as e:
        logger.error(f"Error processing {file}: returned {e.returncode}", enqueue=True)
        return None

def get_meta_from_pcap(pcap_data_path, meta_data_path):
    """
        Generate metadata from pcap files.
    """

    # make output directory if it doesn't exist
    os.makedirs(meta_data_path, exist_ok=True)

    # get list of pcap files
    pcap_files = [os.path.join(pcap_data_path, f) for f in os.listdir(pcap_data_path)]

    logger.info(f"Found {len(pcap_files)} pcap files", enqueue=True)

    # # limit number of files for testing
    # pcap_files = pcap_files[2:3]
    
    logger.info(f"Processing {len(pcap_files)} pcap files", enqueue=True)

    # extract features from pcap files
    with Pool(NUM_CORES) as p:
        p.map(extract_features, pcap_files)

    # wait for all processes to finish
    p.close()