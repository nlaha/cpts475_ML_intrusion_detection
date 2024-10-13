import os
import duckdb
import pandas as pd

data_path = os.path.join('data_merged_extracted', 'clean')
output_path = os.path.join('data_merged_extracted')

# global duckdb connection
con = duckdb.connect(os.path.join(output_path, 'clean_pcap_metadata.duckdb'))

# read all TSV files in the output path
# import them into a single table

# get all TSV files in the output path
tsv_files = [f for f in os.listdir(data_path) if f.endswith('.tsv')]
tsv_files = [os.path.join(data_path, f) for f in tsv_files]

# merge the TSV files into a single table
print("Merging TSV files into a single table")

# create a table in the duckdb database
# with the same schema as the TSV files
print("Creating a table in the duckdb database")
sql = """
    CREATE TABLE IF NOT EXISTS data_merged (
        frame_time_epoch DOUBLE,
        frame_time_delta DOUBLE,
        frame_protocols VARCHAR,
        frame_len BIGINT,
        frame_encap_type INT,
        ip_src VARCHAR,
        ip_dst VARCHAR,
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
        tcp_flags_fin BOOLEAN
    )
"""
con.execute(sql)

# copy each TSV file into the duckdb database
for tsv_file in tsv_files:
    print(f"Copying {tsv_file} into the duckdb database")
    sql = f"INSERT INTO data_merged SELECT * FROM read_csv_auto('{tsv_file}', delim='\t', header=true)"
    con.execute(sql)

# close the duckdb connection
con.close()