#main library from open-quantum-safe
import oqs
import os
from pprint import pprint
from time import sleep
#dependency library for oqs
from cryptography.fernet import Fernet
from serverend import get_pwd, sign_msg, pq_hash
import hashlib

#using key exchange newhope
kex = 'NewHope-1024-CCA'

def qc_check(file_name,file_server):
    client_end_hash = hashlib.sha3_512()
    with open(file_name,'rb') as verification:
        BLOCK_SIDE_C = 65536
        file_ver = verification.read(BLOCK_SIDE_C)
        while len(file_ver) > 0:
            client_end_hash.update(file_ver)
            file_ver = verification.read(BLOCK_SIDE_C)
    if(client_end_hash.hexdigest() == pq_hash(file_server)):
        #print()
        print('Quantum safe hash verified')
    else:
        print('File Manipulated')

def cls_scr():
    if os.name == 'posix':
        _ = os.system('clear')
    else:
        _ = os.system('cls')

key_exchange = 'NewHope-1024-CCA'

with oqs.KeyEncapsulation(key_exchange) as client:
    cls_scr()
    print('Client Side')
    print('Client Details')
    pprint(client.details)
    #public key generation
    public_key = client.generate_keypair()
    pq_file_pwd = get_pwd(public_key)
    file_pwd = client.decap_secret(pq_file_pwd)
    print('Secret key recieved by client')
    print(file_pwd)
    sleep(8)
    cls_scr()
    print("next up quantum signature verification")
    sleep(3)

sig_alg = 'DILITHIUM_2'

print("Post Quantum signature scheme dilithium2 demonstration")
with oqs.Signature(sig_alg) as client:
    cls_scr()
    print("Client side")
    pprint(client.details)
    sleep(5)
    # cls_scr()
    pub_key,sign,msg = sign_msg()
    if client.verify( msg, sign, pub_key):
        print("Message verified")
        print('Message from server')
        print(msg.decode())
    else:
        print("Verification Failed")

sleep(5)
cls_scr()
print('Post Quantum File Integrity check')
file_name = input("Input client end file name")
file_server = input("Input server end file name")

qc_check(file_name,file_server)



