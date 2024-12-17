#!/usr/bin/python3
import argparse
import paho.mqtt.client as mqtt
import ssl
import sys

CERTIFICATE_PATH = "/etc/ssl/server_certificate/server.pem"


def on_message(client, _userdata, message):
    print(f"{message.payload.decode()}")
    client.loop_stop()
    sys.exit(0)


def on_connect(client, _userdata, _flags, rc):
    if rc == 0:
        client.subscribe("meshnet", qos=0)
    else:
        print(f"Failed to connect with result code: {rc}")
        sys.exit(1)

def main(mqtt_broker_host, mqtt_broker_port, mqtt_broker_user, mqtt_broker_password):

    mqttc = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2, client_id="receiver", protocol=mqtt.MQTTv311
    )

    mqttc.on_connect = on_connect
    mqttc.on_message = on_message

    mqttc.username_pw_set(
        username=mqtt_broker_user,
        password=mqtt_broker_password,
    )
    mqttc.tls_set(
        ca_certs=CERTIFICATE_PATH,
        certfile=CERTIFICATE_PATH,
        keyfile=CERTIFICATE_PATH,
        tls_version=ssl.PROTOCOL_TLSv1_2,
        cert_reqs=ssl.CERT_REQUIRED,
    )
    mqttc.connect(mqtt_broker_host, port=mqtt_broker_port, keepalive=1)
    mqttc.loop_start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT Client")

    parser.add_argument("mqtt_broker_host", type=str, help="MQTT broker host")
    parser.add_argument("mqtt_broker_port", type=int, help="MQTT broker port")
    parser.add_argument("mqtt_broker_user", type=str, help="MQTT broker user")
    parser.add_argument("mqtt_broker_password", type=str, help="MQTT broker password")

    args = parser.parse_args()
    main(
        args.mqtt_broker_host,
        args.mqtt_broker_port,
        args.mqtt_broker_user,
        args.mqtt_broker_password,
    )
