import base64

import pymongo
from flask import json
from threading import Thread

from paho.mqtt import subscribe, publish

"""
def on_message_print(client, userdata, message):
	print(message.topic)
	print(message.payload.decode('UTF-8'))


def t1():
	subscribe.callback(on_message_print, "espmqtt15@gmail.com/ESP240AC45EEEC0/dsw1", hostname="mqtt.wifi-iot.com", auth={'username': 'espmqtt15@gmail.com', 'password': '626d0de3'})


thread = Thread(target=t1)
thread.start()

data = json.loads('{"value": false}')
print(str(data['value']).lower())
"""

client = pymongo.MongoClient(
    "mongodb+srv://pluser:iBmyIueKzpxtPEht@smarthome.42feq.mongodb.net/test?retryWrites=true&w=majority")
db = client["test"]
collection = db["test"]

# collection.insert_many([{"id": "2", "test1": 1, "test2": "2", "test3": True}, {"id": "3", "test1": 3, "test2": "4", "test5": False}])
print(str(collection.find_one()["_id"]))
client.close()
