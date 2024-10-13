import os
import re
import duckdb
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

output_path = os.path.join('data_merged_extracted')

# global duckdb connection
con = duckdb.connect(os.path.join(output_path, 'clean_pcap_metadata.duckdb'))

AGG_COLUMNS = [
    'eth_type',
    'ip_src',
    'ip_dst',
]

# plot the number of attacks over time as a bar plot
# sql = """
#     SELECT strftime('%d-%H-%M', timestamp) time_group, count(is_attack) count
#     FROM data_merged 
#     WHERE is_attack = true 
#     GROUP BY strftime('%d-%H-%M', timestamp)
# """
# result = con.execute(sql).df()

# print(result)

# plt.figure(figsize=(20, 10))
# sns.barplot(x='time_group', y='count', data=result)
# plt.xticks(rotation=45)
# plt.title('Number of attacks over time')
# plt.show()

# plot the frame_len distribution for attacks and non-attacks
sql = """
    SELECT is_attack, frame_len
    FROM data_merged WHERE frame_len IS NOT NULL
    USING SAMPLE 10%
"""
result = con.execute(sql).df()

plt.figure(figsize=(20, 10))
sns.histplot(result, x='frame_len', hue='is_attack', bins=100, kde=True)
plt.title('frame_len distribution for attacks and non-attacks')
plt.show()