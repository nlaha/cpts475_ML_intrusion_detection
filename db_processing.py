import os
import re
import duckdb
import pandas as pd

output_path = os.path.join('data_merged_extracted')

# global duckdb connection
con = duckdb.connect(os.path.join(output_path, 'clean_pcap_metadata.duckdb'))

AGG_COLUMNS = [
    'eth_type',
    'ip_src',
    'ip_dst',
]

ATTACKER_IPS = [
    '18.221.219.4',
    '172.31.70.4',
    '172.31.70.6',
    '13.58.98.64',
    '172.31.70.46',
    '18.219.211.138',
    '18.217.165.70',
    '172.31.70.23',
    '13.59.126.31',
    '172.31.70.16',
    '18.219.193.20',
    '18.218.115.60',
    '18.219.9.1',
    '18.219.32.43',
    '18.218.55.126',
    '52.14.136.135',
    '18.219.5.43',
    '18.216.200.189',
    '18.218.229.235',
    '18.218.11.51',
    '18.216.24.42',
    '18.218.115.60',
    '13.58.225.34',
    '18.219.211.138'
]

ATTACKER_IPS_STR = ','.join(map(lambda x: f"'{x}'", ATTACKER_IPS))

print("Adding is_attack column to data_merged table")
print(ATTACKER_IPS_STR)

# create column is_attack in data_merged table
try:
    sql = """
        ALTER TABLE IF data_merged ADD COLUMN is_attack BOOLEAN
    """
    con.execute(sql)
except Exception as e:
    print(e)

# create timestamp column in data_merged table from the frame_time_epoch column
try:
    sql = """
        ALTER TABLE data_merged ADD COLUMN timestamp TIMESTAMP
    """
    con.execute(sql)
    
    # update the timestamp column in data_merged table
    sql = """
        UPDATE data_merged SET timestamp = to_timestamp(frame_time_epoch)
    """

    con.execute(sql)
    
except Exception as e:
    print(e)

# print the number of rows in the merged table
sql = f"""
        UPDATE data_merged SET is_attack = CASE
            WHEN ip_src IN ({ATTACKER_IPS_STR}) THEN true
            WHEN ip_dst IN ({ATTACKER_IPS_STR}) THEN true
            ELSE false
        END
    """

print(sql)
con.execute(sql)