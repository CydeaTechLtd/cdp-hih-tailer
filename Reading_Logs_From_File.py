import socket
import ssl
import schedule
import time
import logging
import os

connections = False
lock = False
def get_config():
    try:
        obj={"siem":"","port":"","logs_file_path": "","certificate_path":"","certificate_password": "","sysmon_logs": "","scapy_log":"","file_logs":"","server_address": ""}
        siem=str(os.environ['SIEM'])
        port = os.environ['SIEM_PORT']
        file_path= str(os.environ['EVTX_LOGS_PATH'])
        certificate_path= str(os.environ['CERTIFICATE_PATH'])
        certificate_password= str(os.environ['CERTIFICATE_PASSWORD'])
        sysmon_logs= str(os.environ['SYSMON_LOG_FILE'])
        server_address= str(os.environ['SERVER_ADDRESS'])
        scapy_log= str(os.environ['SCAPY_LOG_FILE'])
        file_logs= str(os.environ['FILE_LOGS'])

        obj["siem"] = siem
        obj["port"] = port
        obj["logs_file_path"]=file_path
        obj["certificate_path"]=certificate_path
        obj["certificate_password"]=certificate_password
        obj["sysmon_logs"]=sysmon_logs
        obj["server_address"]=server_address
        obj["scapy_log"]=scapy_log
        obj["file_logs"] = file_logs

        return obj
    except Exception as e:
      logging.error("error", e)
obj=get_config()

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
    successfull_entry= False
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
                successfull_entry  = True
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
    return successfull_entry

def read_file(file_name):
        try:
          file1 = open(file_name, 'r+')
          Lines = file1.readlines()
          successfull_entry = False
          for line in Lines:
              successfull_entry=write_on_secure_socket(eval(line.strip()))
          if successfull_entry == True:
             file1.truncate(0)
        except Exception as e:
            logging.error("File Not Found",e)


def scheduler():
    schedule.every(10).minutes.do(lambda: read_file(obj['scapy_log']))
    schedule.every(10).minutes.do(lambda: read_file(obj['sysmon_logs']))
    schedule.every(10).minutes.do(lambda: read_file(obj["file_logs"]))

    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == '__main__':
    scheduler()