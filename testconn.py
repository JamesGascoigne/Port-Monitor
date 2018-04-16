from __future__ import print_function

import MySQLdb

db = MySQLdb.connect(host="localhost",
                user="root",
                passwd="jgazza97",
                db="Ips"
                )

print(db)

cursor = db.cursor()

print(cursor)

number_of_rows = cursor.execute("select * from IPAddress");

print(number_of_rows)
