from subprocess import run
import socket
import requests
import time
import yaml
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["5g-security"]
mycol = mydb["testcases"]


HOST = "127.0.0.1"
PORT = 1337 

with open('./test.yml', 'r') as file:
    testcases = yaml.safe_load(file)

imsi = testcases['imsi']
print(imsi)
print(testcases)
print("#Testcases: " + str(len(testcases["testcases"])))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    for i in range(len(testcases["testcases"])):
        print(testcases['testcases'][i])
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr} 1")
            enc = testcases["ciphering"]
            try:
                enc = testcases['testcases'][i]['sel_ciphering']
            except:
                pass
            conn.sendall(enc.to_bytes(1, 'big'))
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr} 2")
            integrity = testcases["integrity"]
            try:
                integrity = testcases['testcases'][i]['sel_integrity']
            except:
                pass
            conn.sendall(integrity.to_bytes(1, 'big'))
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr} 3")
            data = conn.recv(1024)
            pkt = data.hex()

            print("Original: " + pkt)

            mac = ""
            try:
                mac = testcases['testcases'][i]['mac']
                pkt = pkt[:4] + mac + pkt[12:]
            except:
                pass
                
            ia = testcases['testcases'][i]['integrity']
            ea = testcases['testcases'][i]['ciphering']

            # EA | IA

            pkt = pkt[:20] + hex(ea)[2:] + hex(ia)[2:] + pkt[22:]
            print("Modified: " + pkt)

            conn.sendall(bytes.fromhex(pkt))
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr} 4")
            data = conn.recv(1)
            print(data)
            res = testcases["testcases"][i]

            if (data == b'\x01'):
                print("COMPLETE")
                res["result"] = "COMPLETE"
                res["cause"] = ""
                time.sleep(5)
                url = f'http://127.0.0.5:7777/namf-callback/v1/{imsi}/dereg-notify'
                run("""curl -X POST -d  '{"deregReason": "REREGISTRATION_REQUIRED", "accessType": "3GPP_ACCESS"}' --http2-prior-knowledge """ + url, shell=True)
            else:
                print("REJECT")
                data = conn.recv(10)
                res["result"] = "REJECT"
                res["cause"] = data.hex()
                print("CAUSE: ", data.hex())

            mycol.insert_one(res)

