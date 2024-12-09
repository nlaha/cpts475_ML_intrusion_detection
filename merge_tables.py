from config import DUCKDB_PATH
import duckdb

if __name__ == '__main__':
    # merge tables with _agg suffix into "merged_aggregated" table
    con = duckdb.connect(DUCKDB_PATH)
    tables = con.execute("SHOW TABLES").fetchall()
    tables = [t[0] for t in tables]

    tables_to_merge = [t for t in tables if t.endswith("_agg")]
    if len(tables_to_merge) == 0:
        print("No tables to merge")
        exit()

    print(f"Merging {len(tables_to_merge)} tables into 'merged_aggregated' table")

    # create the merged_aggregated table
    con.execute(f"CREATE TABLE merged_aggregated AS (SELECT * FROM {tables_to_merge[0]})")

    # merge the tables
    for table in tables_to_merge[1:]:
        print(f"Merging {table}")
        con.execute(f"INSERT INTO merged_aggregated SELECT * FROM {table}")
    
    print("Finished merging tables")
