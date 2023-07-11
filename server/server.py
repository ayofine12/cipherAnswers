import socket
import time

class Server:
    def __init__(self, host = '127.0.0.1', port = 3030):
        self.host = host
        self.port = port

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.clients = []
        self.nicknames = {}
        self.file_nicknames = {}

        self.initiater = None
        self.accepter = None

    def receive(self):
        while len(self.clients) < 2:
            client, address = self.server.accept()
            print(f"Connected with {str(address)}")

            client.send('NICK'.encode('utf-8'))
            s = client.recv(1024).decode('utf-8')

            result = s.split(",")
            nickname = result[0]
            f = result[1]

            self.nicknames[nickname] = client
            self.file_nicknames[f] = nickname
            self.clients.append(client)

            print(f"Nickname of the client is {nickname}!")
            print()
            client.send("Connected to the server".encode('utf-8'))

    def inform_nickname(self):
        for target_client in self.clients:
            for nick in self.nicknames:
                target_client.send(nick.encode('utf-8'))
                time.sleep(0.2)
                
    def select_initiater(self):
        initiater_nick = self.file_nicknames['c1']
        accepter_nick = self.file_nicknames['c2']

        print("initiater: ", initiater_nick)
        print("accepter: ", accepter_nick)
        print()

        initiater_client = self.nicknames[initiater_nick]
        accepter_client = self.nicknames[accepter_nick]

        self.initiater = initiater_client
        self.accepter = accepter_client

        initiater_client.send('initiater'.encode('utf-8'))
        accepter_client.send('accepter'.encode('utf-8'))

    def convey_encrypted_con(self):
        encrypted_con = (self.initiater).recv(1024)
        (self.accepter).send(encrypted_con)

    def initiater2accepter(self):
        mac_ciphertext = self.initiater.recv(1024)
        print("initiater2accepter mac_ciphertext")
        print(mac_ciphertext)
        print()
        self.accepter.send(mac_ciphertext)

    def accepter2initiater(self):
        mac_ciphertext = self.accepter.recv(1024)
        print("accepter2initiater mac_ciphertext")
        print(mac_ciphertext)
        print()
        self.initiater.send(mac_ciphertext)

    def convey_ciphertext(self):
        count = 0
        while count < 5:
            self.initiater2accepter()
            self.accepter2initiater()
            count += 1
        

if __name__ == "__main__":
    server = Server()
    server.receive()

    time.sleep(2)

    server.inform_nickname()

    server.select_initiater()

    server.convey_encrypted_con()

    server.convey_ciphertext()

    server.server.close()
