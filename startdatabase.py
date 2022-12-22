import os
import sqlite3

conn = sqlite3.connect(os.environ["DATABASE_OF_IPS"].replace("\\","/"))
cursor = conn.cursor()

# Create the table
cursor.execute("CREATE TABLE IF NOT EXISTS ipinfo (ip TEXT PRIMARY KEY, dns_name TEXT)")

# Commit the changes
conn.commit()

# Close the connection
conn.close()

print("database loaded")