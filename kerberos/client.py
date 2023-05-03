# client.py
import socket
import random
import helpers

session_keys = {'Kca': 3, 'Kct': 4, 'Kts': 5}


class Client:
    def __init__(self):
        # create client socket object
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_to_server(self, address, port):
        # get the IP address of the server and port
        server_address = (address, port)
        # connect to the server on the specified port
        self.client_socket.connect(server_address)

    def get_user_info(self):
        print('-' * 40)
        print("|Kerberos Authenticator| - Client Side")
        print('-' * 40)

        # get the username and password from the user
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        user_info = {'username': username, 'password': password}

        return user_info

    def initiate(self, user_info):
        global session_keys
        print("---initiate function is called---")
        hash_pw = helpers.hash_password(user_info['password'])
        # encrypt the password with session key Kca
        encrypted_password = helpers.encrypt(hash_pw, session_keys['Kca'])
        # print the username and encrypted password
        print('Username: ', user_info['username'],
              '\nEncrypted hashed password:\n', encrypted_password)

        # send the username and encrypted password to the KDC
        print('Sending username and encrypted hashed password to the KDC...>>>')
        helpers.request_animation(is_forwarding=True)
        self.client_socket.sendall(
            bytes(user_info['username'] + ':' + encrypted_password, 'utf-8'))

        # receive the TGT from the KDC
        self.tgt = self.client_socket.recv(1024).decode()

        if self.tgt == 'None':
            print("Auth Failed - Invalid Credentials")
            return None

        print('Received encrypted TGT: ', self.tgt)
        # decrypt TGT with session key Kct
        self.tgt = helpers.decrypt(self.tgt, session_keys['Kct'])
        print(
            f'Client decrypts TGT with session key Kct...Got: {self.tgt}')

        print('Storing TGT to memory for the next authentication...')
        return self.tgt

    def request_ticket(self, username):
        global session_keys
        print("\n---request_ticket function is called---")
        print('Client wants to use the Email Service')
        # A nonce is a number used only once in a cryptographic communication protocol to prevent replay attacks
        self.nonce = random.randint(1, 9)
        print('Client generates a nonce: ', self.nonce)
        tgt_to_encrypt = self.tgt + ':' + \
            username + ':' + str(self.nonce) + ':' + str(105)
        encrypted_tgt = helpers.encrypt(tgt_to_encrypt, session_keys['Kct'])
        print('Encrypted TGT with username and nonce: ', encrypted_tgt)
        print('Sending encrypted TGT to the TGS...>>>')
        helpers.request_animation(is_forwarding=True)
        self.client_socket.sendall(bytes(encrypted_tgt, 'utf-8'))

        # receive the encrypted Service Ticket from TGS
        data = self.client_socket.recv(1024).decode()
        print('Client received Encrypted Service Ticket from TGS.')
        self.Kcs_enc_Kct, self.Kcs_enc_Kts, self.tempstr1 = data.split(
            ':')
        received_nonce = self.tempstr1.split('|')[2]

        print(f'Extracting Nonce from TGS...Got: {received_nonce}')
        print(
            f'Extracting encrypted session key from TGS...Got: {self.Kcs_enc_Kct}')
        self.Kcs = int(helpers.decrypt(self.Kcs_enc_Kct, session_keys['Kct']))
        print(f'Decrypting session key...Got: {self.Kcs}')
        session_keys['Kcs'] = self.Kcs
        self.verify_data_integrity(received_nonce)

    def request_service(self, service_id):
        print('--- \nrequest_service function is called---')
        # Client update nonce
        self.nonce = self.nonce + 1
        service_ticket = self.Kcs_enc_Kts + ':' + \
            str(self.nonce) + ':' + str(service_id)
        # encrypt service_ticket using Kcs
        encrypted_service_ticket = helpers.encrypt(
            service_ticket, session_keys['Kcs'])
        print(
            f'Client is encrypting Token...Got: {encrypted_service_ticket}')
        print('Sending encrypted Token to the requested service...>>>')
        helpers.request_animation(is_forwarding=True)
        self.client_socket.sendall(bytes(encrypted_service_ticket, 'utf-8'))

        # receive the response from the requested service
        response = self.client_socket.recv(1024).decode()
        print('Client received response from the requested service.')
        print('Response: ', response)

    def verify_data_integrity(self, new_nonce):
        print('Verifying nonce...')
        if new_nonce != self.nonce:
            print('Nonce is fresh.')
        else:
            print('Nonce has not been changed.')

    def close_connection(self):
        # close the connection
        print('Closing client connection...')
        self.client_socket.close()


def main():
    # create a client object
    client = Client()
    # connect to the server
    client.connect_to_server(helpers.SERVER_ADDRESS, 8000)
    # get the user info
    user_info = client.get_user_info()
    if user_info is not None:
        # initiate the Kerberos protocol
        tgt = client.initiate(user_info)
        if tgt is not None:
            # request a ticket for the user
            client.request_ticket(username=user_info['username'])
            # request the desired service
            service_id = 105  # Email service
            client.request_service(service_id)
    # close the connection
    client.close_connection()


if __name__ == "__main__":
    main()
