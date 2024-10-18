import os
import duckdb
from loguru import logger

from config import DUCKDB_PATH, TSHARK_DB_COLS

def merge_tsv_files(meta_data_path, table_name):
    """
        Merge the TSV files in the meta_data_path 
        into a single table in the duckdb database
    """
    
    # global duckdb connection
    con = duckdb.connect(DUCKDB_PATH)

    try:
        con.execute(f"SELECT * FROM {table_name} LIMIT 1")
        logger.info(f"Table {table_name} already exists, skipping merging")
        return
    except:
        pass

    # read all TSV files in the output path
    # import them into a single table

    # get all TSV files in the output path
    tsv_files = [f for f in os.listdir(meta_data_path) if f.endswith('.tsv')]
    tsv_files = [os.path.join(meta_data_path, f) for f in tsv_files]

    logger.info(f"Found {len(tsv_files)} TSV files in {meta_data_path}")

    # create a table in the duckdb database
    # with the same schema as the TSV files
    logger.info("Creating a table in the duckdb database")
    sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            {TSHARK_DB_COLS}
        )
    """
    con.execute(sql)

    # copy each TSV file into the duckdb database
    idx = 0
    for tsv_file in tsv_files:
        logger.info(f"Copying {tsv_file} into the duckdb database {idx + 1}/{len(tsv_files)}")
        # timestamp and attack_type columns will be added later
        sql = f"INSERT INTO {table_name} SELECT * FROM read_csv_auto('{tsv_file}', delim='\t', header=true)"
        con.execute(sql)
        idx += 1

    # close the duckdb connection
    con.close()