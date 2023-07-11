import socket
from Crypto.Random import get_random_bytes
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import hmac
import hashlib

class Client:
    def __init__(self, nickname, host = '127.0.0.1', port = 3030, position = 'initiater'):
        self.nickname = nickname
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))
        self.position = position
        self.aes_encoder = None
        self.aes_decoder = None
        self.mac_key = None

    def setting(self):
        count = 0
        while count < 2:
            message = self.client.recv(1024).decode('utf-8')
            if message == 'NICK':
                s = self.nickname + ',' + 'c2'
                self.client.send(s.encode('utf-8'))
            else:
                print(message)
                print()
            count+=1

    def receive_nicks(self):
        count = 0
        while count < 2:
            nick = self.client.recv(1024).decode('utf-8')
            if nick != self.nickname:
                print("nickname of oppoent is: ", nick)
                self.opponent = nick
            count +=1 

    def receive_encrypted_con(self):
        with open('privkey2.pem', 'rb') as f:
            privkey2 = rsa.PrivateKey.load_pkcs1(f.read())

        encrypted_con = self.client.recv(1024)
        decrypted_con = rsa.decrypt(encrypted_con, privkey2)

        aes_key = decrypted_con[:16]
        iv = decrypted_con[16:32]
        mac_key = decrypted_con[32:]

        self.aes_encoder = AES.new(aes_key, AES.MODE_CBC, iv)
        self.aes_decoder = AES.new(aes_key, AES.MODE_CBC, iv)
        self.mac_key = mac_key

    def send_message(self):
        plaintext = input("you: ")
        print()
        padded_plaintext = pad(plaintext.encode(), AES.block_size)
        ciphertext = self.aes_encoder.encrypt(padded_plaintext)
        sender_mac = hmac.new(self.mac_key, ciphertext, hashlib.sha256)
        t = sender_mac.hexdigest()
        t_bytes = bytes.fromhex(t)
        self.client.send(t_bytes+ciphertext)

    def recv_message(self):
        mac_cipher = self.client.recv(1024)
        t_bytes = mac_cipher[:32]
        t_ = t_bytes.hex()
        ciphertext = mac_cipher[32:]

        receiver_mac = hmac.new(self.mac_key, ciphertext, hashlib.sha256)
        t = receiver_mac.hexdigest()

        if t != t_:
            print("something went wrong")
        else:
            padded_data = self.aes_decoder.decrypt(ciphertext)
            data = unpad(padded_data, AES.block_size)
            print("friend:", data)
            print()

    def run(self):
        count = 0
        while count < 5:
            self.recv_message()
            self.send_message()
            count += 1

if __name__ == "__main__":
    client2 = Client(nickname=input("Choose your nickname: "))
    client2.setting()

    client2.receive_nicks()

    client2.position = client2.client.recv(1024).decode('utf-8')

    print('your position is: ', client2.position)

    client2.receive_encrypted_con()

    client2.run()

    client2.client.close()




