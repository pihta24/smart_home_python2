import paho.mqtt.client as mqttClient
import time

"""
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        global Connected
        Connected = True
    else:
        print("Connection failed")


def on_message(client, userdata, message):
    global stop
    stop = True
    str(message.payload)


stop = False
Connected = False

broker_address = "localhost"
port = 1883
user = "yourUser"
password = "yourPassword"

client = mqttClient.Client("Python")
client.username_pw_set(user, password=password)
client.on_connect = on_connect
client.on_message = on_message

client.connect(broker_address, port=port)

client.loop_start()

while not Connected:
    time.sleep(0.1)

client.subscribe("python/test")

start = time.time()
while time.time() - start < 1:
    if stop:
        print(1)
        break"""
