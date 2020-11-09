import json
import Evtx.Evtx as evtx
import xmltodict
import socket
import ssl
import time
import logging
import os
from datetime import datetime, timedelta

connections = False
lock = False
obj=None

def get_config():
    try:
        obj={"siem":"","port":"","logs_file_path": "","certificate_path":"","certificate_password": "","sysmon_logs": "","server_address": "","organization":""}
        siem=str(os.environ['SIEM'])
        port = os.environ['SIEM_PORT']
        file_path= str(os.environ['EVTX_LOGS_PATH'])
        certificate_path= str(os.environ['CERTIFICATE_PATH'])
        certificate_password= str(os.environ['CERTIFICATE_PASSWORD'])
        sysmon_logs= str(os.environ['SYSMON_LOG_FILE'])
        server_address= str(os.environ['SERVER_ADDRESS'])
        organization= str(os.environ['organization'])

        obj["siem"] = siem
        obj["port"] = port
        obj["logs_file_path"]=file_path
        obj["certificate_path"]=certificate_path
        obj["certificate_password"]=certificate_password
        obj["sysmon_logs"]=sysmon_logs
        obj["server_address"]=server_address
        obj["organization"]=organization

        print(obj)
        return obj
    except Exception as e:
      logging.error("Error ", e)
obj=get_config()
def convert_xml_to_json(data_in_xml):
    try:

        log = json.loads(json.dumps(xmltodict.parse(data_in_xml, attr_prefix=" ", cdata_key="text")))
        log.update({"organization": obj['organization']})
        return log
    except Exception as e:
        logging.error('Error in parsing %s' % e)
def hihp_tailer():
    try:

        with evtx.Evtx(obj['logs_file_path']) as rec:
            oldL = 0
            while True:
                new_event = list(rec.records())
                new_event_count = len(new_event)
                if new_event_count > oldL:
                    while new_event_count > oldL:
                        log = convert_xml_to_json(new_event[oldL].xml())
                        try:
                         event=log['Event']
                         event_data=event['EventData']
                        except Exception as e:
                           print("Fields not found %s" %e)
                        try:
                         for item in event_data['Data']:
                          if "UtcTime" in str(item):
                            date=item['text']
                            try:
                              datetime_object = datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')
                              utc_time = datetime.utcnow() - timedelta(minutes=50)
                              if datetime_object >= utc_time:
                                 write_on_secure_socket(log)
                            except Exception as e:
                                  print("Error in time formatting %s" %e)
                        except Exception as e:
                           print("Error %s" %e)
                        oldL += 1
                else:
                    time.sleep(0.5)
    except FileNotFoundError as e:
        logging.error("File Not Found %s" % e)

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
            data = str(data_report)
            if "Event" and "EventID" in data:
                encoded_report_data = bytes(str(data_report).replace("'", "\""), encoding='utf-8')
            else:
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
        with open(obj['sysmon_logs'], "a") as source:
            json.dump(data_report, source)
            source.write("\n")



if __name__ == '__main__':
    hihp_tailer()

