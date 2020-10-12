import json
import ssl
import logging
from scapy.all import *

import os

from datetime import datetime


def get_config():
    try:
        obj={"siem":"","port":"","logs_file_path": "","certificate_path":"","certificate_password": "","sysmon_logs": "","scapy_log":"","server_address": ""}
        siem=str(os.environ['SIEM'])
        port = os.environ['SIEM_PORT']
        file_path= str(os.environ['EVTX_LOGS_PATH'])
        certificate_path= str(os.environ['CERTIFICATE_PATH'])
        certificate_password= str(os.environ['CERTIFICATE_PASSWORD'])
        sysmon_logs= str(os.environ['SYSMON_LOG_FILE'])
        server_address= str(os.environ['SERVER_ADDRESS'])
        scapy_log= str(os.environ['SCAPY_LOG_FILE'])
        obj["siem"] = siem
        obj["port"] = port
        obj["logs_file_path"]=file_path
        obj["certificate_path"]=certificate_path
        obj["certificate_password"]=certificate_password
        obj["sysmon_logs"]=sysmon_logs
        obj["server_address"]=server_address
        obj["scapy_log"]=scapy_log
        print(obj)
        return obj
    except Exception as e:
      logging.error("error", e)
obj=get_config()
packet =	{
    "decoded": "",
    "time": "",
    "ethernet": {
        "dst" :"",
        "src":"",
        "type":""
        },
    "ip": {
        "version":"",
        "ihl" :"",
        "tos" :"",
        "len":"",
        "id":"",
        "flags":"",
        "frag":"",
        "ttl" :"",
        "proto":"",
        "chksum":"",
        "src":"",
        "dst" :""
        },
    "tcp":{
        "sport"  : "",
        "dport"  : "",
        "seq"  : "",
        "ack"  : "",
        "dataofs"  : "",
        "reserved"  : "",
        "flags"  : "",
        "window"  : "",
        "chksum"  : "",
        "urgptr"  : ""
        }
}

def pkt_callback(pkt):
    for p in pkt:
        time=datetime.utcfromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S')
        packet["decoded"]=str(p)
        packet["time"]=time
        packet["ethernet"]["dst"] =str(p["Ethernet"].dst)
        packet["ethernet"]["src"] =str(p.src)
        packet["ethernet"]["type"] =str(p["IP"])
        packet["ip"]["version"] =str(p.version)
        packet["ip"]["ihl"] =str(p.ihl)
        packet["ip"]["tos"] =str(p.tos)
        packet["ip"]["len"] =str(p.len)
        packet["ip"]["id"] =str(p.id)
        packet["ip"]["flags"] =str(p.flags)
        packet["ip"]["frag"] =str(p.frag)
        packet["ip"]["ttl"] =str(p.ttl)
        packet["ip"]["proto"] =str(p.proto)
        packet["ip"]["chksum"] =str(p.chksum)
        packet["ip"]["src"] =str(p[IP].src)
        packet["ip"]["dst"] =str(p[IP].dst)
        packet["tcp"]["sport"] =str(p.sport)
        packet["tcp"]["dport"] =str(p.dport)
        packet["tcp"]["seq"] =str(p.seq)
        packet["tcp"]["ack"] =str(p.ack)
        packet["tcp"]["dataofs"] =str(p.dataofs)
        packet["tcp"]["reserved"] =str(p.reserved)
        packet["tcp"]["flags"] =str(p.flags)
        packet["tcp"]["window"] =str(p.window)
        packet["tcp"]["chksum"] =str(p.chksum)
        packet["tcp"]["urgptr"] =str(p.urgptr)
        scapy_log = json.dumps(packet)
        write_on_secure_socket(scapy_log)

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
        with open(obj['scapy_log'], "a") as source:
            json.dump(data_report, source)
            source.write("\n")


pkt = sniff(iface="Wi-Fi",filter='tcp', prn=pkt_callback, store=1)
