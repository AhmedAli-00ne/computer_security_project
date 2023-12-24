import socket
import threading
import random
import math
import ast
import secrets
import tkinter as tk
from sympy import mod_inverse
from tkinter import ttk, scrolledtext, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = "192.168.1.18"
PORT = 5555

DARK_GREY = "#121212"
MEDIUM_GREY = "#1F1B24"
OCEAN_BLUE = "#464EB8"
WHITE = "white"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)
KeyPair = {}

# Creating a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
selected_algorithm = None
myusername = []


def GenerateKeyPair():
    Prime = 307
    Primitive = 5
    Secret = random.randint(1, Prime - 2)
    KeyPair["PrivateKey"] = Secret
    KeyPair["PublicKey"] = (Primitive**Secret) % Prime


def connect():
    # Get the IP address from the entry widget
    ip_address = ip_textbox.get()
    # Use the entered IP address or the default one if empty
    if ip_address == "":
        ip_address = HOST
    try:
        # Connect to the server
        client.connect((ip_address, PORT))
        GenerateKeyPair()
        print("Successfully connected to server")
        add_message("[SERVER] Successfully connected to the server")
    except:
        messagebox.showerror(
            "Unable to connect to server",
            f"Unable to connect to server {ip_address} {PORT}",
        )
    myusername.append(username_textbox.get())
    if myusername[0] != "":
        client.sendto(f"{myusername[0]}~{KeyPair['PublicKey']}".encode(), (HOST, PORT))
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty")
    threading.Thread(target=listen_for_messages_from_server, args=(client,)).start()
    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)


def listen_for_messages_from_server(client):
    while 1:
        message = client.recv(2048).decode("utf-8")
        if len(message.split("~")) > 2:
            if message != "":
                username = message.split("~")[0]
                content = message.split("~")[1]
                if myusername[0] != username:
                    KeyPair["SessionKey"] = (
                        int(message.split("~")[3]) ** KeyPair["PrivateKey"] % 307
                    )
                PK = message.split("~")[3]
                add_message(f"[{username}] {content}")
            else:
                messagebox.showerror("Error", "Message recevied from client is empty")
        else:
            if message != "":
                username = message.split("~")[0]
                PK = message.split("~")[1]
                if myusername[0] != username:
                    KeyPair["SessionKey"] = int(PK) ** KeyPair["PrivateKey"] % 307
            else:
                messagebox.showerror("Error", "Message recevied from client is empty")


def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + "\n")
    message_box.config(state=tk.DISABLED)


def on_combobox_select(event):
    selected_value = combo_var.get()
    print(f"Selected value: {selected_value}")


def send_message():
    message = message_textbox.get()
    # selected_algorithm = combo_var.get()
    if message != "":
        if selected_algorithm == "Caesar cipher":
            shift = random.randint(1, 10)
            encrypted_message = encrypt_caesar(message, shift)
            client.sendto(
                f"{encrypted_message}~{selected_algorithm}".encode(), (HOST, PORT)
            )
        if selected_algorithm == "Two keys (RSA)":
            encrypted_message = encrypt(message, KeyPair["PublicKey"])
            client.sendto(
                f"{encrypted_message}~{selected_algorithm}~{KeyPair['PublicKey']}".encode(),
                (HOST, PORT),
            )
        if selected_algorithm == "RC4":
            rc4_key = str(secrets.token_bytes(key_length_bits // 8))
            encrypted_message, decrypted_result = RC4_encrypt_decrypt(message, rc4_key)
            client.sendto(
                f"{encrypted_message}~{selected_algorithm}".encode(), (HOST, PORT)
            )
        if selected_algorithm == "Two keys (EL GAMAL)":
            encrypt_elgamal(message)
            client.sendto(
                f"{encrypted_message}~{selected_algorithm}~{KeyPair['PublicKey']}".encode(),
                (HOST, PORT),
            )
        else:
            client.sendto(
                f"{message}~{selected_algorithm}~{KeyPair['PublicKey']}".encode(),
                (HOST, PORT),
            )
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")


# ---------------------------------------------------------------algorithms------------------------------------------------------------------------


# caesar cipher
def encrypt_caesar(message, shift):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            # Shift only alphabetical characters
            if char.islower():
                encrypted_message += chr((ord(char) - ord("a") + shift) % 26 + ord("a"))
            else:
                encrypted_message += chr((ord(char) - ord("A") + shift) % 26 + ord("A"))
        else:
            # Keep non-alphabetical characters unchanged
            encrypted_message += char
    return encrypted_message


def decrypt_caesar(ciphertext, shift):
    decrypted_message = ""
    for char in ciphertext:
        if char.isalpha():
            shifted_char = (
                chr((ord(char) - shift - ord("A")) % 26 + ord("A"))
                if char.isupper()
                else chr((ord(char) - shift - ord("a")) % 26 + ord("a"))
            )
            decrypted_message += shifted_char
        else:
            decrypted_message += char
    return decrypted_message


# rsa
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def is_prime(n, k=5):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    while k > 0:
        a = random.randint(2, n - 2)
        x = pow(a, n - 1, n)
        if x != 1:
            return False
        k -= 1
    return True


def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Commonly used value for e
    d = modinv(e, phi)

    return ((n, e), (n, d))


def encrypt(message, public_key):
    n, e = public_key
    encrypted_msg = [pow(ord(char), e, n) for char in message]
    return encrypted_msg


def decrypt(encrypted_msg, private_key):
    n, d = private_key
    decrypted_msg = [chr(pow(char, d, n)) for char in encrypted_msg]
    return "".join(decrypted_msg)


# RC4
def S_vector(key):
    S = list(range(256))
    T = [ord(key[i % len(key)]) for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def initial_permutation(S, size):
    i = 0
    j = 0
    K = []
    for _ in range(size):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        T = (S[i] + S[j]) % 256
        K.append(S[T])
    return K


def RC4_encrypt_decrypt(plaintext, key):
    encrypted_data = []
    S = S_vector(key)
    K = initial_permutation(S, len(plaintext))

    for i in range(len(plaintext)):
        encrypted_data.append(ord(plaintext[i]) ^ K[i])

    decrypted_data = ""
    # Convert the encrypted_data list back to a string for decryption
    ciphertext = encrypted_data
    S = S_vector(key)
    K = initial_permutation(S, len(ciphertext))

    for i in range(len(ciphertext)):
        decrypted_data += chr(ciphertext[i] ^ K[i])

    return encrypted_data, decrypted_data


# ElGamal
def encrypt_elgamal(plaintext_list):
    p, g, h = (307, 5, KeyPair["PublicKey"])
    ciphertext_list = []
    plaintext_list = [ord(char) for char in plaintext_list]
    for char in plaintext_list:
        k = random.randint(1, p - 2)
        c1 = pow(g, k, p)
        c2 = (pow(h, k, p) * char) % p
        ciphertext_list.append((c1, c2))
    return ciphertext_list


def extract_numbers_from_string(input_string):
    result = []

    current_number = ""
    for char in input_string:
        if char.isdigit():
            current_number += char
        elif current_number:
            result.append(int(current_number))
            current_number = ""

    if current_number:
        result.append(int(current_number))

    return result


def decrypt_elgamal(ciphertext_list):
    result_list = extract_numbers_from_string(ciphertext_list)
    ciphertext_list = []
    for i in range(0, len(result_list)):
        if (i == 0 or i % 2 == 0) and i != len(result_list):
            ciphertext_list.append((result_list[i], result_list[i + 1]))

    print(f"ciphertext_list : {ciphertext_list}")
    p = 307
    dh_private_key = KeyPair["PrivateKey"]
    decrypted_list = []

    for c1, c2 in ciphertext_list:
        s = pow(c1, dh_private_key, p)  # Use dh_private_key instead of a
        s_inv = mod_inverse(s, p)
        plaintext = (c2 * s_inv) % p
        decrypted_list.append(plaintext)
    print(f"decrypted_list : {decrypted_list}")

    decrypted_list = "".join(
        [chr(char) if 32 <= char <= 126 else "<?>" for char in decrypted_list]
    )
    print(f"decrypted_list Elgamal : {decrypted_list}")
    return decrypted_list


# -------------------------------------------------------------Algorithm------------------------------------------------------------------------


key_length_bits = 128


def encrypt_button_click():
    print("encrypt")
    message = message_textbox.get()
    selected_val = combo_var.get()

    rc4_key = str(secrets.token_bytes(key_length_bits // 8))
    # des_key= public_key_textbox.get()
    # des_key=pad(des_key)
    if selected_val == "Single key (DES)":
        message = message_textbox.get()
    elif selected_val == "Caesar cipher":
        shift = random.randint(1, 10)
        ciphertext = encrypt_caesar(message, shift)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
    elif selected_val == "Two keys (EL GAMAL)":
        ciphertext = encrypt_elgamal(message)
        print(f"ciphertext Elgamal : {ciphertext}")

        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
    elif selected_val == "Two keys (RSA)":
        p = generate_random_prime()
        q = generate_random_prime()
        if not (is_prime(p) and is_prime(q)):
            print("Both p and q should be prime numbers.")
        else:
            public_key, private_key = generate_keypair(p, q)
            encrypted_message = encrypt(message, public_key)
            ciphertext_entry.delete(0, tk.END)
            ciphertext_entry.insert(0, encrypted_message)
    elif selected_val == "RC4":
        encrypted_result, decrypted_result = RC4_encrypt_decrypt(message, rc4_key)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, encrypted_result)


def decrypt_button_click():
    selected_val = combo_var.get()
    rc4_key = str(secrets.token_bytes(key_length_bits // 8))
    ciphertext_hex = ciphertext_entry.get()
    message = message_textbox.get()
    # des_key= public_key_textbox.get()
    # des_key=pad(des_key)

    if selected_val == "Single key (DES)":
        ciphertext = bytes.fromhex(ciphertext_hex)
        # decrypted_message = decrypt_des(ciphertext, des_key)
        # decrypted_entry.delete(0, tk.END)
        # decrypted_entry.insert(0, decrypted_message)
    elif selected_val == "Caesar cipher":
        shift = random.randint(1, 10)
        decrypted_message = decrypt_caesar(ciphertext_hex, shift)
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_message)
    elif selected_val == "Two keys (EL GAMAL)":
        # print(f"cipher msg Elgamal : {message}")
        decrypted_message = decrypt_elgamal(ciphertext_hex)
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_message)
    elif selected_val == "Two keys (RSA)":
        p = generate_random_prime()
        q = generate_random_prime()
        public_key, private_key = generate_keypair(p, q)
        encrypted_message = encrypt(message, public_key)
        decrypted_message = decrypt(encrypted_message, private_key)
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_message)

    elif selected_val == "RC4":
        encrypted_result, decrypted_result = RC4_encrypt_decrypt(message, rc4_key)
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_result)


def combined_command():
    encrypt_button_click()
    decrypt_button_click()
    send_message()


def generate_random_prime():
    while True:
        random_number = random.randint(1, 200)
        if is_prime(random_number):
            return random_number


# Create the main window
root = tk.Tk()
root.geometry("1135x600")
root.title("Messenger Client with DES Encryption")
root.resizable(False, False)

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)
bottom_frame2 = tk.Frame(root, width=200, height=100, bg=DARK_GREY)
bottom_frame2.grid(row=4, column=0, sticky=tk.NSEW)

# private_key_label = tk.Label(bottom_frame2, text="Private Key:", font=FONT, bg=DARK_GREY, fg=WHITE)
# private_key_label.pack(side=tk.LEFT, padx=10)

# private_key_textbox = tk.Entry(bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=15)
# private_key_textbox.pack(side=tk.LEFT, padx=10)

# public_key_label = tk.Label(bottom_frame2, text="Public Key:", font=FONT, bg=DARK_GREY, fg=WHITE)
# public_key_label.pack(side=tk.LEFT, padx=10)

# public_key_textbox = tk.Entry(bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=15)
# public_key_textbox.pack(side=tk.LEFT, padx=10)

prime_number_label = tk.Label(
    bottom_frame2, text="prime number:", font=FONT, bg=DARK_GREY, fg=WHITE
)
prime_number_label.pack(side=tk.LEFT, padx=10)

prime_number_textbox = tk.Entry(
    bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=5
)
prime_number_textbox.pack(side=tk.LEFT, padx=10)

single_primitive_root_label = tk.Label(
    bottom_frame2, text="primitive root:", font=FONT, bg=DARK_GREY, fg=WHITE
)
single_primitive_root_label.pack(side=tk.LEFT, padx=10)

single_primitive_root_textbox = tk.Entry(
    bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=5
)
single_primitive_root_textbox.pack(side=tk.LEFT, padx=10)

secret_number_label = tk.Label(
    bottom_frame2, text="secret number:", font=FONT, bg=DARK_GREY, fg=WHITE
)
secret_number_label.pack(side=tk.LEFT, padx=10)

secret_number_textbox = tk.Entry(
    bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=5
)
secret_number_textbox.pack(side=tk.LEFT, padx=10)

# shift_label = tk.Label(bottom_frame2, text="shift:", font=FONT, bg=DARK_GREY, fg=WHITE)
# shift_label.pack(side=tk.LEFT, padx=10)

# shift_textbox = tk.Entry(bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=5)
# shift_textbox.pack(side=tk.LEFT, padx=10)

# P_label = tk.Label(bottom_frame2, text="P:", font=FONT, bg=DARK_GREY, fg=WHITE)
# P_label.pack(side=tk.LEFT, padx=10)

# P_textbox = tk.Entry(bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=5)
# P_textbox.pack(side=tk.LEFT, padx=10)

# q_label = tk.Label(bottom_frame2, text="q:", font=FONT, bg=DARK_GREY, fg=WHITE)
# q_label.pack(side=tk.LEFT, padx=10)

# q_textbox = tk.Entry(bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=5)
# q_textbox.pack(side=tk.LEFT, padx=10)

# RC4_label = tk.Label(bottom_frame2, text="Rc4 key:", font=FONT, bg=DARK_GREY, fg=WHITE)
# RC4_label.pack(side=tk.LEFT, padx=10)

# RC4_textbox = tk.Entry(bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=5)
# RC4_textbox.pack(side=tk.LEFT, padx=10)


username_label = tk.Label(
    top_frame, text="Enter username:", font=FONT, bg=DARK_GREY, fg=WHITE
)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
username_textbox.pack(side=tk.LEFT)

ip_label = tk.Label(
    top_frame, text="Enter server IP:", font=FONT, bg=DARK_GREY, fg=WHITE
)
ip_label.pack(side=tk.LEFT, padx=10)

ip_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=15)
ip_textbox.pack(side=tk.LEFT)

username_button = tk.Button(
    top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect
)
username_button.pack(side=tk.LEFT, padx=15)

message_textbox = tk.Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=38)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(
    bottom_frame,
    text="Send",
    font=BUTTON_FONT,
    bg=OCEAN_BLUE,
    fg=WHITE,
    command=combined_command,
)
message_button.pack(side=tk.LEFT, padx=10)

combo_var = tk.StringVar()
combo = ttk.Combobox(
    bottom_frame2,
    textvariable=combo_var,
    values=[
        "Single key (DES)",
        "Single key (AES(256))",
        "Two keys (RSA)",
        "Two keys (EL GAMAL)",
        "RC4",
        "Caesar cipher",
    ],
)
combo.set("CHOOSE ENCRYPTION ALGORITHM")
combo.bind("<<ComboboxSelected>>", on_combobox_select)
combo.pack(side=tk.BOTTOM, pady=10, padx=10)

message_box = scrolledtext.ScrolledText(
    middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=77, height=26.5
)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)


ciphertext_label = ttk.Label(bottom_frame, text="Ciphertext:")
ciphertext_label.pack(side=tk.LEFT, padx=10)

ciphertext_entry = ttk.Entry(bottom_frame, width=15)
ciphertext_entry.pack(side=tk.LEFT, padx=10)

decrypt_button = ttk.Button(bottom_frame, text="Decrypt", command=decrypt_button_click)
decrypt_button.pack(side=tk.LEFT, padx=10)

decrypted_label = ttk.Label(bottom_frame, text="Decrypted Message:")
decrypted_label.pack(side=tk.LEFT, padx=10)

decrypted_entry = ttk.Entry(bottom_frame, width=15)
decrypted_entry.pack(side=tk.LEFT, padx=10)

root.mainloop()
