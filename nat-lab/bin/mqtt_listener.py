import paho.mqtt.client as mqtt
import sys


def on_message(_client, _userdata, message):
    print(f"{message.payload.decode()}")
    sys.exit(0)


mqttc = mqtt.Client(client_id="reciever", protocol=mqtt.MQTTv311)

mqttc.on_message = on_message

# TODO: add credentials when LLT-5604 will be ready
mqttc.connect("10.0.80.85", port=1883, keepalive=1)
mqttc.subscribe("meshnet", qos=0)

mqttc.loop_forever()
