#!/bin/python3
import sqlite3
import argparse
import os

def print_sql_content(database_file):
    os.system(f'if [ -f "{database_file}" ]; then    echo "File exists: {database_file}";fi')
    try:
        conn = sqlite3.connect(database_file)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        for table in tables:
            table_name = table[0]
            print(f"Table: {table_name}")
            cursor.execute(f"SELECT * FROM {table_name};")
            rows = cursor.fetchall()
            for row in rows:
                print(row)
        conn.close()
    except sqlite3.Error as e:
        print("SQLite error:", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Print the content of an SQLite3 database file.")
    parser.add_argument("--sql", type=str, help="Path to the SQLite3 database file, usage: --sql=blog.sql", required=True)
    args = parser.parse_args()
    print_sql_content(args.sql)
