import tailer
import json
import os
import ssl
import logging
import socket

packet =	{
    "time": "",
    "action": "",
    "paths": "",
    "user": ""
}
def get_config():
    try:
        obj={"siem":"","port":"","logs_file_path": "","certificate_path":"","certificate_password": "","file_logs_path": "","sysmon_logs": "","scapy_log":"","file_logs":"","server_address": ""}
        siem=str(os.environ['SIEM'])
        port = os.environ['SIEM_PORT']
        file_path= str(os.environ['EVTX_LOGS_PATH'])
        certificate_path= str(os.environ['CERTIFICATE_PATH'])
        certificate_password= str(os.environ['CERTIFICATE_PASSWORD'])
        sysmon_logs= str(os.environ['SYSMON_LOG_FILE'])
        server_address= str(os.environ['SERVER_ADDRESS'])
        scapy_log= str(os.environ['SCAPY_LOG_FILE'])
        file_logs= str(os.environ['FILE_LOGS'])
        file_logs_path = str(os.environ["FILE_LOGS_PATH"])
        obj["siem"] = siem
        obj["port"] = port
        obj["logs_file_path"]=file_path
        obj["certificate_path"]=certificate_path
        obj["certificate_password"]=certificate_password
        obj["sysmon_logs"]=sysmon_logs
        obj["server_address"]=server_address
        obj["scapy_log"]=scapy_log
        obj["file_logs"] = file_logs
        obj["file_logs_path"] = file_logs_path
        return obj
    except Exception as e:
      logging.error("error", e)
obj=get_config()
def read_file_logs():
  for line in tailer.follow(open(obj["file_logs_path"])):
    file_data=str(line).split(",")
    packet["time"]=str(file_data[0])
    packet["action"]=str(file_data[1])
    packet["file_path"] =file_data[2]
    packet["user"] = file_data[3]
    file_log=json.dumps(packet)
    write_on_secure_socket(file_log)
    print(file_log)
def connection_socket():
    server_cert = obj['certificate_path']
    client_cert = obj['certificate_path']
    client_key = obj['certificate_path']
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1000)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
        context.load_cert_chain(certfile=client_cert, keyfile=client_key, password=obj['certificate_password'])
        conn = context.wrap_socket(s, server_side=False, server_hostname=(obj['server_address']))
        return conn
    except socket.error as e:
        logging.error("Error creating socket: %s" % e)


def write_on_secure_socket(data_report):
    logging.info(data_report)
    conn = connection_socket()
    i = 0
    connected = False
    while not connected and i < 3:
        global connections
        connections = True
        i = i + 1
        try:
            conn.connect((obj['siem'],int(obj['port'])))
            encoded_report_data = bytes(data_report, encoding='utf-8')
            try:
                conn.send(bytes(encoded_report_data))
            except socket.error as e:
                logging.error("Error sending data: %s" % e)
            connected = True
        except socket.timeout as e:
            logging.error("Error is", e)
        except socket.error as err:
            connections = False
            logging.error('Error in socket %s' % err)
        except Exception as e:
            connected = True
            logging.error("Error while connection %s" %e)
    conn.close()
    if connections == False:
        with open(obj["file_logs"], "a") as source:
            json.dump(data_report, source)
            source.write("\n")

if __name__ == '__main__':
    read_file_logs()