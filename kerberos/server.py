# server.py
import socket
import helpers
import string
import random

"""
Kct: the secret key shared between the client and ticket-granting server
Kts: the secret key shared between the ticket-granting server and the application server
Kca: the secret key shared between the client and the authentication server
"""
session_keys = {'Kca': 3, 'Kct': 4, 'Kts': 5}
nonce = None  # nonce used in verification at client side for integrity checking
services = {'105': 'Email Service', '106': 'File Service'}


class KeyDistCenter:
    def __init__(self, username):
        self.username = username
        self.database = {'team4': '1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032',  # letmein is plaintext
                         'admin': 'password', }

    # authenticate the user and return the TGT

    def authenticate(self, username, password):
        print('--- KDC - Authentication Server (AS) is called---')
        global session_keys
        # check if the username is valid
        if username in self.database.keys():
            print('AS is checking user identity...')
            dec_pw = helpers.decrypt(password, session_keys['Kca'])
            # check if the password is correct
            if self.database[username] == dec_pw:
                print('USER IS AUTHENTICATED! GENERATING TGT...')
                # generate 16-bit alphanumeric TGT and return it.
                self.TGT = ''.join(random.choices(
                    string.ascii_letters + string.digits, k=16))
                print('TGT: ', self.TGT)
                # encrypt TGT with Kct
                encrypted_tgt = helpers.encrypt(self.TGT, session_keys['Kct'])
                print('Encrypted TGT: ', encrypted_tgt)
                return encrypted_tgt
            else:
                print('INVALID CREDENTIALS')
                return
        else:
            print('INVALID CREDENTIALS')
            return

    def grant_ticket(self, encrypted_data):
        global session_keys, nonce
        print('--- KDC - Ticket Granting Server (TGS) is called---')
        decrypted_data = helpers.decrypt(encrypted_data, session_keys['Kct'])
        print(f'TGS is decrypting data...Got: {decrypted_data}')
        arrs = decrypted_data.split(':')
        decrypted_tgt = arrs[0]
        username = arrs[1]
        nonce1 = arrs[2]
        service_id = arrs[3]

        print('Client is requesting service: ', services[service_id])
        print(f'Extracting TGT...Got: {decrypted_tgt}')
        print('TGS is verifying TGT...')
        if decrypted_tgt == self.TGT:
            print('TGT is valid!')
        else:
            print('TGT has been tampered!')

        # update nonce used in verification at client side for integrity checking
        new_fresh_nonce = int(nonce1) + 1
        # save the nonce to the server
        nonce = new_fresh_nonce
        print('Updated nonce: ', new_fresh_nonce)
        # generate new session key Kcs that will be used for encrypting messages between the client and server.
        Kcs = random.randint(1, 9)
        session_keys['Kcs'] = Kcs

        tempstr1 = '|'.join([str(Kcs), str(username), str(new_fresh_nonce)])
        # encrypt Kcs with Kct and Kts
        print('Encrypting Kcs with Kct and Kts...')
        Kcs_enc_Kct = helpers.encrypt(str(Kcs), session_keys['Kct'])
        Kcs_enc_Kts = helpers.encrypt(str(Kcs), session_keys['Kts'])

        session_Kcs = Kcs_enc_Kct + ':' + Kcs_enc_Kts + ':' + tempstr1
        print(f'Generating Token...Got: {session_Kcs}')
        print('Storing session key Kcs...')

        return session_Kcs


class Server:
    # Define the constructor to run the server
    def __init__(self, address, port):
        self.session_key = None
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bind the socket to a public host, and a well-known port
        self.server_socket.bind((address, port))
        # become a server socket
        self.server_socket.listen(1)
        print('-' * 40)
        print("|Kerberos Authenticator| - Server Side")
        print('-' * 40)
        print('Server is running on port 8000...')

    def accept_initiate_request(self):
        print('>>>--- accept_initiate_request function is called---')
        # accept connections from client
        self.client_socket, addr = self.server_socket.accept()
        print("Got a connection from %s" % str(addr))
        # receive data from client
        data = self.client_socket.recv(1024)
        received_data = data.decode('utf-8')
        username, enc_pw = received_data.split(':')
        print('Received username: ', username)
        print('Received encrypted password:\n', enc_pw)

        return (username, enc_pw)

    def accept_request_ticket_request(self):
        print('>>>--- accept_request_ticket_request function is called---')
        data = self.client_socket.recv(1024)
        received_data = data.decode('utf-8')
        print(f'Ticket Granting Service received: {received_data} from client')

        return received_data

    def authenticate_user(self, KDC, username, enc_pw):
        # return to the client that the username is invalid
        self.tgt = str(KDC.authenticate(username, enc_pw))
        # send the TGT to the client
        print(f'<<<---Sending encrypted TGT to client...')
        helpers.request_animation(is_forwarding=False)
        self.client_socket.sendall(self.tgt.encode('utf-8'))

        return None if self.tgt == 'None' else self.tgt

    def get_service_ticket(self, KDC, encrypted_data):
        self.granted_ticket = str(KDC.grant_ticket(encrypted_data))
        # send the service ticket to the client
        print(
            f'<<<---Sending Token: {self.granted_ticket} to client...')
        helpers.request_animation(is_forwarding=False)
        self.client_socket.sendall(self.granted_ticket.encode('utf-8'))

    def accept_service_request(self):
        print('>>>--- accept_service_request function is called---')
        data = self.client_socket.recv(1024)
        received_data = data.decode('utf-8')
        print(f'Service server received: {received_data} from client.')
        return received_data

    def application_server(self, encrypted_data):
        global nonce
        print('--- application_server function is called---')
        decrypted_data = helpers.decrypt(encrypted_data, session_keys['Kcs'])
        print(
            f'Application server is decrypting data from client...Got: {decrypted_data}')
        arrs = decrypted_data.split(
            ":")
        Kcs_enc_Kts = arrs[0]
        received_nonce = arrs[1]
        self.service_id = arrs[2]

        self.verify_nonce_freshness(received_nonce)
        print('Extracting Kcs_enc_Kts...Got: ', Kcs_enc_Kts)
        print('Extracting nonce...Got: ', received_nonce)
        print('Extracting service ID...Got: ', self.service_id)
        self.Kcs = int(helpers.decrypt(Kcs_enc_Kts, session_keys['Kts']))
        print(f'Server decrypts the service ticket...Got: {self.Kcs}')
        print('Verifying Kcs...')
        if self.Kcs == session_keys['Kcs']:
            print('Kcs IS VALID! USER IS AUTHENTICATED')
            print('The User now can use the requested service!')

            message = 'You are authenticated! You can use the requested service!'
            self.client_socket.sendall(message.encode('utf-8'))
        else:
            print('Kcs is invalid! User is not authenticated!')
            message = 'You are not authenticated! You cannot use the requested service!'
            self.client_socket.sendall(message.encode('utf-8'))

    def verify_nonce_freshness(self, new_nonce):
        global nonce
        print('Verifying nonce...')
        if new_nonce != nonce:
            print('Nonce is fresh.')
        else:
            print('Nonce has not been changed.')

    def close_connection(self):
        # close the connection
        print('Closing server connection...')
        self.server_socket.close()


def main():
    # create a server object
    server = Server(helpers.SERVER_ADDRESS, 8000)

    # accept the initiate request and get the user's credentials
    username, password = server.accept_initiate_request()

    # create a Key Distribution Center object and use it to get the TGT
    kdc = KeyDistCenter(username)
    tgt = server.authenticate_user(KDC=kdc, username=username, enc_pw=password)

    # if TGT is obtained, proceed with the ticket request and service request
    if tgt:
        # accept the ticket request and get the encrypted TGT, username, and nonce
        encrypted_tgt_usrname_nonce = server.accept_request_ticket_request()

        # use the KDC to get the service ticket and decrypt it using the TGT
        server.get_service_ticket(kdc, encrypted_tgt_usrname_nonce)

        # accept the service request and authenticate the server
        received_data = server.accept_service_request()
        server.application_server(received_data)

    # close the connection with the server
    server.close_connection()


if __name__ == "__main__":
    main()
