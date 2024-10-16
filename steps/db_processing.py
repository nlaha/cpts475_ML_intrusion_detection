import duckdb
from loguru import logger

from config import DUCKDB_PATH, ATTACK_TYPE_MAPPING

def post_process_database(table_source):
    """
    Post-process the database table (label data)
    Add the attack_type column to the table
    """
    
    table_name = f"{table_source}_agg"
    
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

    logger.info(f"Updating attack_type column in {table_name} table")
    sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} AS
        (
            SELECT
            MAX (
                CASE
                    WHEN ip_src IN ({ATTACKER_IPS_STR}) THEN {ATTACK_TYPE_MAPPING.get(table_name)}
                    WHEN ip_dst IN ({ATTACKER_IPS_STR}) THEN {ATTACK_TYPE_MAPPING.get(table_name)}
                    ELSE 0
                END
            ) AS attack_type,
            strftime('%Y-%m-%d %H:%M',to_timestamp(frame_time_epoch)) as date_minutes

            AVG(frame_time_delta) as avg_frame_time_delta,
            AVG(frame_len) as avg_frame_len,
            AVG(tcp_hdr_len) as avg_tcp_hdr_len,
            
            stddev_samp(frame_time_delta) as stddev_frame_time_delta,
            stddev_samp(frame_len) as stddev_frame_len,
            stddev_samp(tcp_hdr_len) as stddev_tcp_hdr_len,
            
            mode(frame_time_delta) as mode_frame_time_delta,
            mode(frame_len) as mode_frame_len,
            mode(tcp_hdr_len) as mode_tcp_hdr_len,
            
            entropy(frame_time_delta) as entropy_frame_time_delta,
            entropy(frame_len) as entropy_frame_len,
            entropy(tcp_hdr_len) as entropy_tcp_hdr_len,

            median(frame_time_delta) as median_frame_time_delta,
            median(frame_len) as median_frame_len,
            median(tcp_hdr_len) as median_tcp_hdr_len,
            
            COUNT(tcp_flags_syn) as count_tcp_flags_syn,
            COUNT(tcp_flags_fin) as count_tcp_flags_fin,
            COUNT(tcp_flags_reset) as count_tcp_flags_reset,
            COUNT(tcp_flags_push) as count_tcp_flags_push,
            COUNT(tcp_flags_ack) as count_tcp_flags_ack,
            COUNT(tcp_flags_urg) as count_tcp_flags_urg,
            COUNT(tcp_flags_ece) as count_tcp_flags_ece,
            COUNT(tcp_flags_cwr) as count_tcp_flags_cwr,
            COUNT(tcp_flags_ae) as count_tcp_flags_ae,
            COUNT(tcp_flags_res) as count_tcp_flags_res,
            
            MAX(frame_time_delta) as max_frame_time_delta,
            MAX(frame_len) as max_frame_len,
            MAX(tcp_hdr_len) as max_tcp_hdr_len,
            
            MIN(frame_time_delta) as min_frame_time_delta,
            MIN(frame_len) as min_frame_len,
            MIN(tcp_hdr_len) as min_tcp_hdr_len,
            
            FROM {table_source}
            GROUP_BY date_minutes
        )
        """

    con.execute(sql)
    
    # drop the old table
    sql = f"""
        DROP TABLE {table_source}
    """
    con.execute(sql)
