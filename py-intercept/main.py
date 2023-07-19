from subprocess import run
import socket
import requests
import time
import yaml

HOST = "127.0.0.1"
PORT = 1337 

with open('test.yml', 'r') as file:
    testcases = yaml.safe_load(file)

imsi = testcases['imsi']
print(imsi)
print(testcases['testcases'][0])
print(testcases['testcases'][1])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        for i in range(len(testcases)):
            data = conn.recv(1024)
            pkt = data.hex()

            print(pkt)

            mac = testcases['testcases'][i]['mac']
            print(mac[2:])
            ia = testcases['testcases'][i]['integrity']
            ea = testcases['testcases'][i]['ciphering']

            # MAC
            pkt = pkt[:4] + mac + pkt[12:]
            # EA | IA
            pkt = pkt[:20] + str(ea) + str(ia) + pkt[22:]
            print(pkt)
            if i==0:
                conn.sendall(data)
            else:
                conn.sendall(bytes.fromhex(pkt))

            time.sleep(5)

            url = f'http://127.0.0.5:7777/namf-callback/v1/{imsi}/dereg-notify'
            run("""curl -X POST -d  '{"deregReason": "REREGISTRATION_REQUIRED", "accessType": "3GPP_ACCESS"}' --http2-prior-knowledge """ + url, shell=True)

