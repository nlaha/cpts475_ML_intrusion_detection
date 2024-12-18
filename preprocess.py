"""
    Process the raw data files and extract 
    the pcap files from their archives
"""

import os
import subprocess
from loguru import logger

from config import SOURCE_DATA_DIR, SEVENZIP_PATH, PCAP_DATA_PATH, META_DATA_PATH, DATA_SUBSET_MAPPING

from steps.extract_features import get_meta_from_pcap
from steps.merge_data import merge_tsv_files
from steps.db_processing import post_process_database

if __name__ == '__main__':

    # log source data directory
    logger.info(f"Source data directory: {SOURCE_DATA_DIR}")
 
    # iterate through each subdirectory of SOURCE_DATA_DIR
    for root, dirs, files in os.walk(SOURCE_DATA_DIR):
        for directory in dirs:
            logger.info(f"Processing data subset {directory}")

            data_subset = os.path.join(root, directory)
            # get the data subset name
            data_subset_name = DATA_SUBSET_MAPPING.get(directory)
            if data_subset_name is None:
                data_subset_name = "benign"
      
            # extract the pcap files for this data subset
            # find the destination directory for the extracted pcap files
            subset_destination_dir = os.path.join(PCAP_DATA_PATH, data_subset_name)
            destination_dir = os.path.join(subset_destination_dir, directory)
            meta_dir = os.path.join(META_DATA_PATH, data_subset_name, directory)
            
            # skip if it already contains files
            if not os.path.exists(meta_dir):
                # check if the destination directory exists
                os.makedirs(destination_dir)
                    
                # the pcap files are either pcap.zip or pcap.rar
                # use SEVENZIP_PATH to extract the files
                pcap_archive = list(filter(lambda x: 'pcap' in x, os.listdir(data_subset)))[0]
                
                logger.info(f"Extracting {pcap_archive} to {destination_dir}")
                
                # extract the pcap files
                # extract the files directly into the destination directory, don't add a pcap subdirectory
                command = f"{SEVENZIP_PATH} e \"{os.path.abspath(os.path.join(data_subset, pcap_archive))}\" -y -bsp1 -o\"{os.path.abspath(destination_dir)}\" pcap/*"
                # run the subprocess and print the output live
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for line in process.stdout:
                    logger.info(line.decode('utf-8').strip())
                for line in process.stderr:
                    logger.error(line.decode('utf-8').strip())
                process.wait()
                
                # check if the extraction was successful
                if process.returncode == 0:
                    logger.info(f"Successfully extracted pcap files for {data_subset_name}/{directory}")
                else:
                    logger.error(f"Error extracting pcap files for {data_subset_name}/{directory}")

            else:
                logger.info(f"Extracted pcap files already exist for {data_subset_name}/{directory}")
                       
            # check if the metadata files already exist
            if not os.path.exists(os.path.join(META_DATA_PATH, data_subset_name, directory)):

                # run the metadata extraction script
                logger.info("Running metadata extraction")
                
                get_meta_from_pcap(destination_dir, os.path.join(META_DATA_PATH, data_subset_name, directory))
                
                logger.info("Finished metadata extraction")
            else:
                logger.info(f"Metadata directory already exists for {data_subset_name}/{directory}, skipping metadata extraction")
            
            if os.path.exists(destination_dir):
                # delete the extracted pcap files to save space
                logger.info("Deleting extracted pcap files")
                for f in os.listdir(destination_dir):
                    os.remove(os.path.join(destination_dir, f))
                os.rmdir(destination_dir)
                logger.info("Finished deleting extracted pcap files")
            
            # table
            table_name = f"{data_subset_name}_{directory}".replace("-", "_")
            
            logger.info(f"Merging metadata files into {table_name} table")
            
            # merge the metadata files into a single duckdb table
            merge_tsv_files(os.path.join(META_DATA_PATH, data_subset_name, directory), table_name)
            
            logger.info(f"Finished merging metadata files into {table_name} table")
            
            # labeling & processing database table
            logger.info(f"Aggregating {table_name} table")
            
            post_process_database(table_name, directory)
            
            logger.info(f"Finished aggregating {table_name} table")
            
    logger.info("Finished processing all data subsets")
    