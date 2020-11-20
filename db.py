import sqlite3

from flask import json
from werkzeug.security import generate_password_hash

db_path = 'data.db'  # путь к базе данных(str)

db = sqlite3.connect(db_path, check_same_thread=False)
cursor = db.cursor()

# cursor.execute("drop table sensors")
# cursor.execute("create table users(id INTEGER PRIMARY KEY AUTOINCREMENT, email VARCHAR(150), password VARCHAR(100), def_mqtt_server VARCHAR(100), def_mqtt_port VARCHAR(10), def_mqtt_pass VARCHAR(50), def_mqtt_login VARCHAR(50))")
# cursor.execute("create table tokens(id INTEGER, token VARCHAR(100))")
# cursor.execute("create table controllers(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, set_topic VARCHAR(5), name VARCHAR(60), devices_count INTEGER, mqtt_server VARCHAR(100), mqtt_port VARCHAR(10), mqtt_pass VARCHAR(50), mqtt_login VARCHAR(50))")
# cursor.execute("create table devices(id INTEGER PRIMARY KEY AUTOINCREMENT, controller_id INTEGER, user_id INTEGER, my_type VARCHAR(50), my_type_rus VARCHAR(50), type VARCHAR(50), name VARCHAR(100))")
# cursor.execute("create table devices_properties(device_id INTEGER, my_type VARCHAR(50), ya_type VARCHAR(50), instance VARCHAR(50), value VARCHAR(50))")
# cursor.execute("create table queue(data TEXT)")
# cursor.execute("create table sensors(id INTEGER PRIMARY KEY AUTOINCREMENT, controller_id INTEGER, device_id INTEGER, user_id INTEGER, value FLOAT, instance VARCHAR(50), topic TEXT, name VARCHAR(100), instance_rus VARCHAR(50))")
