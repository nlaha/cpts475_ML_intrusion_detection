import os
import duckdb
from loguru import logger

from config import DUCKDB_PATH

def merge_tsv_files(meta_data_path, table_name):
    """
        Merge the TSV files in the meta_data_path 
        into a single table in the duckdb database
    """
    
    # global duckdb connection
    con = duckdb.connect(DUCKDB_PATH)

    # read all TSV files in the output path
    # import them into a single table

    # get all TSV files in the output path
    tsv_files = [f for f in os.listdir(meta_data_path) if f.endswith('.tsv')]
    tsv_files = [os.path.join(meta_data_path, f) for f in tsv_files]

    logger.info(f"Found {len(tsv_files)} TSV files in {meta_data_path}")

    # check if we already have a table with the same name
    # if so, drop the table
    try:
        con.execute(f"DROP TABLE {table_name}")
    except Exception as e:
        logger.warning(e)

    # create a table in the duckdb database
    # with the same schema as the TSV files
    logger.info("Creating a table in the duckdb database")
    sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
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
        logger.info(f"Copying {tsv_file} into the duckdb database")
        sql = f"INSERT INTO {table_name} SELECT * FROM read_csv_auto('{tsv_file}', delim='\t', header=true)"
        con.execute(sql)

    # close the duckdb connection
    con.close()