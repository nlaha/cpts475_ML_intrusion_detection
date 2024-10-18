import duckdb
from loguru import logger

from config import DUCKDB_PATH, ATTACK_TYPE_MAPPING, ATTACK_TIMES, ATTACKER_IPS

def post_process_database(table_source, attack_date):
    """
    Post-process the database table (label data)
    Add the attack_type column to the table
    """

    logger.info(f"Using attack_date = {attack_date}")
    
    table_name = f"{table_source}_agg"
    
    # global duckdb connection
    con = duckdb.connect(DUCKDB_PATH)
    
    # if we already have the table, return
    try:
        con.execute(f"SELECT * FROM {table_name} LIMIT 1")
        logger.info(f"Table {table_name} already exists, skipping post-processing")
        return
    except:
        pass
    
    # filter attack_times by attack_date
    attack_times_filtered = list(filter(lambda x: attack_date == x[0], ATTACK_TIMES))
    
    logger.info(f"Using {', '.join(map(lambda x: x[3], attack_times_filtered))} as attack types")

    # build the WHEN clause for the attack_type column
    then_clause = ""
    for time in attack_times_filtered:
        start_time = time[1]
        end_time = time[2]
        attack_name = time[3]
        
        start_minutes = int(start_time.split(":")[0]) * 60 + int(start_time.split(":")[1])
        end_minutes = int(end_time.split(":")[0]) * 60 + int(end_time.split(":")[1])
        
        then_clause += f"""
            WHEN minutes
                BETWEEN {start_minutes} AND {end_minutes} THEN {ATTACK_TYPE_MAPPING[attack_name]}
        """
        
    logger.info(f"Using then_clause: {then_clause}")

    ATTACKER_IPS_REGEX = "|".join(map(lambda x: f"({x})", ATTACKER_IPS))

    logger.info(f"Aggregating data to {table_name} table")
    sql = f"""
        CREATE TABLE IF NOT EXISTS {table_name} AS
        (
            SELECT
            
            MAX (
                CASE
                    WHEN regexp_matches(ip_src, '{ATTACKER_IPS_REGEX}') THEN 1
                    WHEN regexp_matches(ip_dst, '{ATTACKER_IPS_REGEX}') THEN 1
                    ELSE 0
                END
            ) AS has_attack_ip,
            
            MAX (
                CASE
                    {then_clause}
                    ELSE {ATTACK_TYPE_MAPPING['Benign']}
                END
            ) AS attack_type,
            
            date_minutes,
            
            avg(frame_time_delta) as avg_frame_time_delta,
            avg(frame_len) as avg_frame_len,
            avg(tcp_hdr_len) as avg_tcp_hdr_len,
            avg(tcp_time_relative) as avg_tcp_time_relative,
            
            stddev_samp(frame_time_delta) as stddev_frame_time_delta,
            stddev_samp(frame_len) as stddev_frame_len,
            stddev_samp(tcp_hdr_len) as stddev_tcp_hdr_len,
            stddev_samp(tcp_time_relative) as stddev_tcp_time_relative,
            
            mode(frame_time_delta) as mode_frame_time_delta,
            mode(frame_len) as mode_frame_len,
            mode(tcp_hdr_len) as mode_tcp_hdr_len,
            mode(tcp_time_relative) as mode_tcp_time_relative,
            
            entropy(frame_time_delta) as entropy_frame_time_delta,
            entropy(frame_len) as entropy_frame_len,
            entropy(tcp_hdr_len) as entropy_tcp_hdr_len,
            entropy(tcp_time_relative) as entropy_tcp_time_relative,

            median(frame_time_delta) as median_frame_time_delta,
            median(frame_len) as median_frame_len,
            median(tcp_hdr_len) as median_tcp_hdr_len,
            median(tcp_time_relative) as median_tcp_time_relative,
            
            count(tcp_flags_syn = true) as count_tcp_flags_syn,
            count(tcp_flags_fin = true) as count_tcp_flags_fin,
            count(tcp_flags_reset = true) as count_tcp_flags_reset,
            count(tcp_flags_push = true) as count_tcp_flags_push,
            count(tcp_flags_ack = true) as count_tcp_flags_ack,
            count(tcp_flags_urg = true) as count_tcp_flags_urg,
            count(tcp_flags_ece = true) as count_tcp_flags_ece,
            count(tcp_flags_cwr = true) as count_tcp_flags_cwr,
            count(tcp_flags_ae = true) as count_tcp_flags_ae,
            count(tcp_flags_res = true) as count_tcp_flags_res,
            
            count(contains(frame_protocols, 'tcp')) as count_proto_tcp,
            count(contains(frame_protocols, 'udp')) as count_proto_udp,
            count(contains(frame_protocols, 'tls')) as count_proto_tls,
            count(contains(frame_protocols, 'http')) as count_proto_http,
            count(contains(frame_protocols, 'smb')) as count_proto_smb,
            count(contains(frame_protocols, 'rdp')) as count_proto_rdp
            
            FROM (
                SELECT 
                    *,
                    strftime(to_timestamp(frame_time_epoch), '%Y-%m-%d %H:%M') as date_minutes,
                    hour(to_timestamp(frame_time_epoch)) * 60 + minute(to_timestamp(frame_time_epoch)) as minutes
                FROM {table_source}
            )
            GROUP BY date_minutes
        )
        """

    con.execute(sql)