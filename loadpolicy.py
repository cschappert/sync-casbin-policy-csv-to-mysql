import csv
import mysql.connector

# connect to db
conn = mysql.connector.connect(
    host="127.0.0.1",
    port=3306,
    user="user",
    password="password",
    database="database"
)

# get a cursor
cursor = conn.cursor()

# add policy of model 'p, sub, obj, act'
add_policy = """
    insert into casbin_rule(p_type, v0, v1, v2)
    select 'p', %(v0)s, %(v1)s, %(v2)s from DUAL
    where not exists (
        select 1 from casbin_rule
        where p_type = 'p' and v0 = %(v0)s and v1 = %(v1)s and v2 = %(v2)s
    );
"""

# add group of model 'g, _, _'
add_group = """
    insert into casbin_rule(p_type, v0, v1)
    select 'g', %(v0)s, %(v1)s from DUAL
    where not exists (
        select 1 from casbin_rule
        where p_type = 'g' and v0 = %(v0)s and v1 = %(v1)s
    );
"""

with open("policy.csv", newline="") as f:
    reader = csv.reader(f)
    for row in reader:
        if row[0] == "g":
            params = {'v0': row[1], 'v1': row[2]}
            cursor.execute(add_group, params)
        elif row[0] == "p":
            params = {'v0': row[1], 'v1': row[2], 'v2': row[3]}
            cursor.execute(add_policy, params)
        # log executed SQL statement to standard out
        print(cursor.statement)
        print("\n")

# commit and close
conn.commit()
cursor.close()
conn.close()
