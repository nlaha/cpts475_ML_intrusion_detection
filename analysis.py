import duckdb
import matplotlib.pyplot as plt
import seaborn as sns

from config import DUCKDB_PATH

# global duckdb connection
con = duckdb.connect(DUCKDB_PATH)

AGG_COLUMNS = [
    'eth_type',
    'ip_src',
    'ip_dst',
]

# print number of attacks and non-attacks
sql = """
    SELECT is_attack, count(*) count
    FROM data_merged
    GROUP BY is_attack
"""
result = con.execute(sql).df()

print(result)

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

# compute a metric to compare the number of attacks per second and group the data by the metric
sql = """
    SELECT strftime('%d-%H-%M', timestamp) time_group, 
           SUM(CASE WHEN is_attack THEN 1 ELSE 0 END) * 1.0 / COUNT(*) attack_rate
    FROM data_merged 
    GROUP BY strftime('%d-%H-%M', timestamp)
"""

result = con.execute(sql).df()

# print the attack rate over time
print(result)

# plot the attack rate over time as a line plot
plt.figure(figsize=(20, 10))
sns.lineplot(x='time_group', y='attack_rate', data=result)
plt.xticks([])
plt.title('Attack rate over time')
plt.show()