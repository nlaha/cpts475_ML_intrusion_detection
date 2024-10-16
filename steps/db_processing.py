import duckdb
from loguru import logger

from config import DUCKDB_PATH, ATTACK_TYPE_MAPPING

def post_process_database(table_name):
    """
    Post-process the database table (label data)
    Add the attack_type column to the table
    """
    
    # global duckdb connection
    con = duckdb.connect(DUCKDB_PATH)

    AGG_COLUMNS = [
        "eth_type",
        "ip_src",
        "ip_dst",
    ]

    ATTACKER_IPS = [
        "18.221.219.4",
        "172.31.70.4",
        "172.31.70.6",
        "13.58.98.64",
        "172.31.70.46",
        "18.219.211.138",
        "18.217.165.70",
        "172.31.70.23",
        "13.59.126.31",
        "172.31.70.16",
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
        "18.218.115.60",
        "13.58.225.34",
        "18.219.211.138",
    ]

    ATTACKER_IPS_STR = ",".join(map(lambda x: f"'{x}'", ATTACKER_IPS))

    logger.info(f"Adding attack_type column to {table_name} table")

    # create column attack_type in table
    try:
        sql = f"""
            ALTER TABLE IF {table_name} ADD COLUMN attack_type INT
        """
        con.execute(sql)
    except Exception as e:
        logger.error(e)

    # create timestamp column in data_merged table from the frame_time_epoch column
    try:
        # check if timestamp column exists
        if "timestamp" in con.table(table_name).columns:
            logger.info("Timestamp column already exists in table")
        else:
            sql = f"""
                ALTER TABLE {table_name} ADD COLUMN timestamp TIMESTAMP
            """
            con.execute(sql)

        # update the timestamp column in data_merged table
        sql = f"""
            UPDATE {table_name} SET timestamp = to_timestamp(frame_time_epoch)
        """

        con.execute(sql)

    except Exception as e:
        logger.error(e)

    # print the number of rows in the merged table
    sql = f"""
            UPDATE {table_name} SET attack_type = CASE
                WHEN ip_src IN ({ATTACKER_IPS_STR}) THEN '{ATTACK_TYPE_MAPPING.get(table_name)}'
                WHEN ip_dst IN ({ATTACKER_IPS_STR}) THEN '{ATTACK_TYPE_MAPPING.get(table_name)}'
                ELSE 0
            END
        """

    con.execute(sql)
