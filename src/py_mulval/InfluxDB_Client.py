from __future__ import print_function

import os
import sys

sys.path.insert(0, os.path.abspath('../'))



import math
import os
import pandas as pd
import time
from datetime import datetime

import matplotlib.pyplot as plt
import numpy as np
from IPython.display import display

from influxdb import InfluxDBClient
from influxdb import DataFrameClient
import pandas as pd

# client = InfluxDBClient('10.0.2.15', 8086, 'perfkit', 'perfkit', 'perfkit')
# client.create_database('example')

# client.write_points(json_body)

# result = client.query('select value from cpu_load_short;')

# print("Result: {0}".format(result))

# print(client.health())

# dbs = client.get_list_database()
# print(dbs)

# DBNAME='sample_database'
DBNAME='perfkit'

config = {
        'host':     '192.168.0.115',
        'port':       8086,
        'database': 'perfkit',
        # 'user':     'perfkit',
        # 'password': 'perfkit',

    }

client = InfluxDBClient(**config)
# client.ping()
res = client.query('SHOW DATABASES')
print(res)
client.ping()

client.create_database(DBNAME)
client.switch_database(DBNAME)

# client = DataFrameClient(**config)
res = client.query('SHOW DATABASES')
# print(type(res), res)
res = client.query('SHOW MEASUREMENTS', database=DBNAME )
# res = client.query('SHOW STATS', database=DBNAME )
# res = client.query('SHOW TABLES', database=DBNAME )
# res = client.query('SHOW RETENTION POLICIES', database=DBNAME )
# res = client.query('SHOW MEASUREMENT CARDINALITY', database=DBNAME )


import pprint
pprint.pprint(list(res))
q = client.query('select * from DBNAME', database=DBNAME)
print(q)



