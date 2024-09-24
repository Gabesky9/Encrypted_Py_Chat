#Version 0_3 -- Adding GUI, ITS PROBABLY SO BROKEN, tkinter is horrible for threading... bet youre wishing you knew that before hey?
import tkinter as tk
from tkinter import scrolledtext
import socket 
import sys
import threading
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os  
#Uncomment the input later, for now just keep IP and PORT as loopback defaults.
key = None
IP = '127.0.0.1'   #Test with the hardcoded vals and worry about the other shit later #input("Please enter the IP of the server you want to connect too:")
PORT = 9999 #Test with the hardcoded vals and worry about the other shit later #input("Please enter the port you wish to host the server on!:  ")
PORT = int(PORT)
ADDR = (IP, PORT)
UNAME = input("Please enter the username you wish to send messages as: ")
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
current_time = datetime.now()
format_time = current_time.strftime("%Y-%m-%d %H:%M:%S")  
EXIT_MSG = 'disconnect'   #Disconnect clients from the server, don't forget to add a -h option. 
PASSWORD = input("Please enter the server password...")
 

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


def start_gui(client):
    root = tk.Tk()
    root.title("SuperSecret Chat App Client")

    chat_window = scrolledtext.ScrolledText(root, width=50, height=20, state=tk.DISABLED)
    chat_window.grid(row=0, column=0, padx=10, pady=10)

    message_input = tk.Entry(root, width=40)
    message_input.grid(row=1, column=0, padx=10, pady=10)

    send_button = tk.Button(root, text='Send', command=lambda: send_message(client, message_input, chat_window))
    send_button.grid(row=1, column=1, padx=10, pady=10)

    threading.Thread(target=recv_message, args=(client, chat_window)).start()
    root.mainloop()  # Start the GUI loop



#My janked out function to recieve messages
def  recv_message(client, chat_window):
    global key
    while True:
        try:
            encrypted_message = client.recv(1024)
            decrypted_message = decrypt_message(encrypted_message, key).decode('utf-8')
            chat_window.config(state=tk.NORMAL)  # Make the chat window editable
            chat_window.insert(tk.END, f"{decrypted_message}\n")  # Append message to the chat window
            chat_window.config(state=tk.DISABLED)  # Disable it to prevent user edits
            chat_window.yview(tk.END)  # Auto-scroll to the latest message
        except Exception as e:
            print(f"Error: {e}")
            break
        except:
            print("An Error has occured while attempting to recieve a message...") #Change this out to throw an expected error once you've tested, if its no big deal just suppress the error
            client.close()
            break

def send_message(client, message_input, chat_window):
    global key

    while True:
        message = message_input.get()
        if message:
            try:                #REMOVE THE CLIENT:: THING AND JUST HAVE THE TIME AND USERNAME, ONLY HAVE SERVER FOR SERVER MESSAGES GABERIONO!!
                client_message = f"[{format_time}]::{UNAME}: {message}"
                encrypted_message = encrypt_message(client_message, key)
                client.send(encrypted_message) #Previous working version of this client.send(encrypted_message) 
                
                chat_window.config(state=tk.NORMAL)
                chat_window.insert(tk.END, f"you: {message} \n")
                chat_window.config(state=tk.DISABLED)
                chat_window.yview(tk.END)

                #Make sure that input field gets cleared
                message_input.delete(0, tk.END)
                
                if message.lower() == EXIT_MSG:
                    print("You are disconnecting from the server...")
                    client.close()
                    break
            except Exception as e:
                print(f"Looks like an error has occurred: {e}")
                break



def start_client():
    global key
    #Heres the REAL code to connect to that diry dirty server
    while True:
        try:
            client.connect(ADDR)
            print(f"Connected to a server on IP:{ADDR} \n and PORT {ADDR}")
            #Get the salt from the server to properly have the same encyrption for each msg on both sides 
            salt = client.recv(16)
            key = generate_key(PASSWORD, salt)
        except:
            print(f"Something went wrong connecting to the server, idk if this ones on me my man \n double check that the following are correct \n IP: {ADDR}")
            return
    
    #Now heres the real "fun" part, THREADING FOR THE CLIENT SIDE, GOOD LUCK FIXING THIS ONE FUTURE GABER
    #You might have to add some better threading to the server side to reliably handle more than fucking five clients bro...

chat_window, root = start_gui(client) 
threading.Thread(target=recv_message, args=(client, chat_window)).start() 



if __name__ == "__main__":
    start_client()
