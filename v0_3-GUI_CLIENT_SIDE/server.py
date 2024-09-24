#Version 0_3 -- Adding GUI, and across separate network testing, thank you Ryan M for helping as a tester <3
import socket
import sys
import threading
from datetime import datetime
import requests #Requests is literally only here to get the public IP to host the server on, this might be a bitch to set up but try it out for the scientist in you
                #Add DearPyGUI here, see if you can put all of the user interface logic into two separate files, then have them compiled in the same folder/exe when this project is close to done for ease of use 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os  

def get_public_ip():    #Function to get the servers public facing IP automatically
    try:                    #When this project is almost done try to impliment this to make it easier/faster for the server owner to start up a server 
        response = requests.get('https://api.ipify.org?format=text')
        return response.text
    except requests.RequestException:
        return "Unable to retrieve your public IP, something went wrong and its probably my fault, sorry about that \n if the entire script hasnt crashed at this point just enter your IP manually "



def prompt_for_ip():
    public_ip = get_public_ip()     
    if public_ip:
        print(f"Successfully automatically retrieved the public IP: {public_ip}")
        use_public_ip = input('Do you wish to use this IP? yes/no: ').strip().lower()
        if  use_public_ip == 'yes':
            return public_ip
    return input("Either I failed to get your public IP, or you selected 'no' \n Enter the IP/Interface you wish to host your server on (Default is localhost): ").strip() 


IP = prompt_for_ip()  # Change to prompt_for_ip after its done (Function is defined below big daddy Gaber)
PORT = 9999 #Just test with the hardcoded values before letting the users set thier own, create better error handling to figure out the issue      #input("Please enter the port you wish to host the server on!: ") 
PORT = int(PORT) #Changing the PORT to an integer cause thats just what needs to be done.
OWNER_NAME = input("Please enter the name you want to be displayed when you send messages as the server owner: ")

PASSWORD = input("Enter the password you wish to use for this server instance: ")
salt = os.urandom(16)   #Share this with teh client
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #Server socket as 's
clients = [] #Array of clients that will connect to the server

current_time = datetime.now() 
format_time = current_time.strftime("%Y-%m-%d %H:%M:%S")    #Formatting the datetime to a string for the messages and whatever the hell else I decide to use it for 

EXIT_MSG = 'disconnect' #Message the server owner can use to close the server by sending




#Encryption Functions
# Generate a shared key (use this in both client and server)
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encrypt the message using AES-GCM
def encrypt_message(message: str, key: bytes):
    iv = os.urandom(12)  # Initialization vector for AES-GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

# Decrypt the message using AES-GCM
def decrypt_message(ciphertext: bytes, key: bytes):
    iv = ciphertext[:12]
    tag = ciphertext[12:28]
    actual_ciphertext = ciphertext[28:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()


key = generate_key(PASSWORD, salt)


def broadcast(message, sender_socket=None):
    for client_socket in clients:
        if client_socket != sender_socket:
            try:
                client_socket.send(message)
            except:
                client_socket.close()
                clients.remove(client_socket)


def handle_client(client_socket):
    while True:
        try:
            # Receive encrypted message
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                # Decrypt the message
                decrypted_message = decrypt_message(encrypted_message, key).decode('utf-8')
                print(f"Decrypted: {decrypted_message}")
                if decrypted_message == EXIT_MSG:
                    print(f"CLIENT: {client_socket} DISCONNECTED...")
                    client_socket.close()                    #CLOSE THAT COWARDS DIRTY SOCKET
                    clients.remove(client_socket)            #THAT THAT LITTLE OFF THE LIST
                    break                                    #MAKE THE LOOP GO BYE BYE,  BYYYE BYYE
            else:
                broadcast(encrypted_message, client_socket) 
                break
        except Exception as e:
            print(f"Error: {e}")
            break



       
       
def send_server_msg():
    while True:
        message = input(f"SERVER::{OWNER_NAME}: ")
        if message:
            if message.lower() == EXIT_MSG:
                print("Shutting down the server...") #GETTING RID OF THE 'SERVER' PART IN THE F STRING COULD CLEAN UP THE WINDOW FOR WHEN U ADD THE GUI?
                broadcast(encrypt_message(f"SERVER:: {current_time}:: {EXIT_MSG} \n The server is shutting down...", key))
                break
            try:
                # Encrypt the server message before broadcasting
                server_message = f"SERVER::[{format_time}]::{OWNER_NAME}: {message}"
                encrypted_server_message = encrypt_message(server_message, key)
                broadcast(encrypted_server_message)
            except Exception as e:
                print(f"Error sending server message: {e}")

def start_server():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket created")

    # Bind the socket to the IP and PORT
    s.bind((IP, PORT))
    print(f'Socket has been bound to {IP}:{PORT}')

    # Listen for incoming connections
    s.listen(5)
    print("Listening for incoming connections...")

    threading.Thread(target=send_server_msg, daemon=True).start() #Threading to handle the server owner sending messages
    while True:
        client_socket, addr = s.accept()
        print(f'Got a connection from {addr}')
        #Send the SALT  to the client
        client_socket.send(salt)
        # Add the client to the list of clients
        clients.append(client_socket)

        # Start a new thread to handle this client's communication
        threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
        


if __name__ == "__main__":
    start_server()
