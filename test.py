import socket
import threading
import random
import math
import secrets
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# from Crypto.Cipher import DES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad
#

HOST = "192.168.100.3"
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

    username = username_textbox.get()
    if username != "":
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty")

    threading.Thread(target=listen_for_messages_from_server, args=(client,)).start()

    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)


def listen_for_messages_from_server(client):
    while 1:
        message = client.recv(2048).decode("utf-8")

        if message != "":
            username = message.split("~")[0]
            content = message.split("~")[1]
            KeyPair["SessionKey"] = (
                int(message.split("~")[3]) ** KeyPair["PrivateKey"] % 307
            )
            PK = message.split("~")[3]
            print(message)
            add_message(f"[{username},{PK},{KeyPair['SessionKey']}] {content}")
        else:
            messagebox.showerror("Error", "Message recevied from client is empty")


def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + "\n")
    message_box.config(state=tk.DISABLED)


def on_combobox_select(event):
    selected_value = combo_var.get()
    print(f"Selected value: {selected_value}")

    # if selected_value == "Single key (DES)":
    #     public_key_textbox.config(state=tk.DISABLED)
    #     shift_textbox.config(state=tk.DISABLED)
    #     private_key_textbox.config(state=tk.NORMAL)
    # elif selected_value == "Caesar cipher":
    #     public_key_textbox.config(state=tk.DISABLED)
    #     private_key_textbox.config(state=tk.DISABLED)
    #     P_textbox.config(state=tk.DISABLED)
    #     q_textbox.config(state=tk.DISABLED)
    #     RC4_textbox.config(state=tk.DISABLED)
    #     shift_textbox.config(state=tk.NORMAL)
    # elif selected_value == "Two keys (RSA)":
    #     public_key_textbox.config(state=tk.DISABLED)
    #     private_key_textbox.config(state=tk.DISABLED)
    #     RC4_textbox.config(state=tk.DISABLED)
    #     shift_textbox.config(state=tk.DISABLED)
    #     P_textbox.config(state=tk.NORMAL)
    #     q_textbox.config(state=tk.NORMAL)
    # elif selected_value == "RC4":
    #     public_key_textbox.config(state=tk.DISABLED)
    #     private_key_textbox.config(state=tk.DISABLED)
    #     shift_textbox.config(state=tk.DISABLED)
    #     P_textbox.config(state=tk.DISABLED)
    #     q_textbox.config(state=tk.DISABLED)
    #     RC4_textbox.config(state=tk.NORMAL)


# def display_message(message):
#     message_box.config(state=tk.NORMAL)
#     message_box.insert(tk.END, message + "\n")
#     message_box.config(state=tk.DISABLED)
#     message_box.see(tk.END)
# def receive_messages(sock):
#     while True:
#         try:
#             data = sock.recv(1024)
#             if not data:
#                 break
#             decrypted_message = decrypt_des(data, des_key)
#             display_message(decrypted_message)
#         except Exception as e:
#             print("Error receiving message:", str(e))
#             break


def send_message():
    message = message_textbox.get()
    selected_algorithm = combo_var.get()
    if message != "":
        if selected_algorithm == "Single key (DES)":
            key = b"8bytekey"  # Use an 8-byte key for DES
            encrypted_message = encrypt_des(message, key)
            client.sendall(f"{encrypted_message}~{selected_algorithm}".encode())
        if selected_algorithm == "Caesar cipher":
            shift = random.randint(1, 10)
            encrypted_message = encrypt_caesar(message, shift)
            client.sendall(f"{encrypted_message}~{selected_algorithm}".encode())
        if selected_algorithm == "Two keys (RSA)":
            encrypted_message = encrypt(message, KeyPair["PublicKey"])
            client.sendall(
                f"{encrypted_message}~{selected_algorithm}~{KeyPair['PublicKey']}".encode()
            )
        if selected_algorithm == "RC4":
            rc4_key = str(secrets.token_bytes(key_length_bits // 8))
            encrypted_message, decrypted_result = RC4_encrypt_decrypt(message, rc4_key)
            client.sendall(f"{encrypted_message}~{selected_algorithm}".encode())
        else:
            client.sendall(
                f"{message}~{selected_algorithm}~{KeyPair['PublicKey']}".encode()
            )
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message", "Message cannot be empty")


# ---------------------------------------------------------------algorithms------------------------------------------------------------------------

# DES ALGORITHM
# def bin_to_hexa(msg):
#   mp = {"0000" : '0',
#         "0001" : '1',
#         "0010" : '2',
#         "0011" : '3',
#         "0100" : '4',
#         "0101" : '5',
#         "0110" : '6',
#         "0111" : '7',
#         "1000" : '8',
#         "1001" : '9',
#         "1010" : 'A',
#         "1011" : 'B',
#         "1100" : 'C',
#         "1101" : 'D',
#         "1110" : 'E',
#         "1111" : 'F' }
#   hex=""
#   for i in range(0,len(msg),4):
#     ch=""
#     ch=ch+msg[i]
#     ch=ch+msg[i+1]
#     ch=ch+msg[i+2]
#     ch=ch+msg[i+3]
#     hex=hex+mp[ch]
#   return hex
# def initial_permutation(block):
#     # Initial permutation table (1-based index)
#     ip_table = [
#         58, 50, 42, 34, 26, 18, 10, 2,
#         60, 52, 44, 36, 28, 20, 12, 4,
#         62, 54, 46, 38, 30, 22, 14, 6,
#         64, 56, 48, 40, 32, 24, 16, 8,
#         57, 49, 41, 33, 25, 17, 9, 1,
#         59, 51, 43, 35, 27, 19, 11, 3,
#         61, 53, 45, 37, 29, 21, 13, 5,
#         63, 55, 47, 39, 31, 23, 15, 7
#     ]

#     # Apply the initial permutation
#     permuted_block = 0
#     for i, bit in enumerate(ip_table):
#         permuted_block |= ((block >> (64 - bit)) & 0x1) << (63 - i)

#     return permuted_block

# def final_permutation(block):
#     # The final permutation is the inverse of the initial permutation
#     final_permutation_table = [
#         40, 8, 48, 16, 56, 24, 64, 32,
#         39, 7, 47, 15, 55, 23, 63, 31,
#         38, 6, 46, 14, 54, 22, 62, 30,
#         37, 5, 45, 13, 53, 21, 61, 29,
#         36, 4, 44, 12, 52, 20, 60, 28,
#         35, 3, 43, 11, 51, 19, 59, 27,
#         34, 2, 42, 10, 50, 18, 58, 26,
#         33, 1, 41, 9, 49, 17, 57, 25
#     ]

#     # Apply the final permutation table
#     permuted_block = 0
#     for i, bit_position in enumerate(final_permutation_table):
#         bit_value = (block >> (64 - bit_position)) & 1
#         permuted_block |= bit_value << i

#     return permuted_block

# def feistel_network(right_half, subkey):
#     # Example Feistel function using XOR
#     expanded_right_half = expand(right_half)
#     xored_data = expanded_right_half ^ subkey
#     substituted_data = substitute(xored_data)
#     permuted_data = permute(substituted_data)
#     return right_half ^ permuted_data

# def expand(data):
#     # Implement the expansion function
#     expansion_table = [
#         32,  1,  2,  3,  4,  5,
#          4,  5,  6,  7,  8,  9,
#          8,  9, 10, 11, 12, 13,
#         12, 13, 14, 15, 16, 17,
#         16, 17, 18, 19, 20, 21,
#         20, 21, 22, 23, 24, 25,
#         24, 25, 26, 27, 28, 29,
#         28, 29, 30, 31, 32,  1
#     ]

#     expanded_data = 0
#     for i, bit_position in enumerate(expansion_table):
#         # Get the bit at the specified position in the original data
#         original_bit = (data >> (32 - bit_position)) & 0x01
#         # Set the corresponding bit in the expanded data
#         expanded_data |= original_bit << (47 - i)

#     return expanded_data

# def substitute(data):
#     # Implement the substitution function
#     substitution_boxes = [
#         [
#             # S-box 1
#             [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
#             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
#             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
#             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
#         ],
#         [
#             # S-box 2
#             [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
#             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
#             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
#             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
#         ],
#         # Include S-boxes 3 to 8
#         # ...
#     ]

#     # Divide the 48-bit data into 6-bit chunks
#     chunks = [(data >> i) & 0x3F for i in range(42, -1, -6)]

#     # Apply substitution for each 6-bit chunk using the corresponding S-box
#     substituted_data = 0
#     for i, chunk in enumerate(chunks):
#         row = ((chunk & 0x20) >> 4) | (chunk & 0x01)  # Extract row bits
#         col = (chunk >> 1) & 0x0F  # Extract column bits
#         substituted_value = substitution_boxes[i][row][col]  # Lookup in S-box
#         substituted_data |= substituted_value << (46 - (i * 4))

#     return substituted_data

# def permute(data, permutation_table):
#     # Implement the permutation function
#     permuted_data = 0
#     for i, position in enumerate(permutation_table):
#         bit = (data >> (32 - position)) & 0x01
#         permuted_data |= bit << (31 - i)

#     return permuted_data

# def des_round(left_half, right_half, subkey):
#     # Implement a single DES round
#     expanded_right_half = expand(right_half)
#     xor_result = expanded_right_half ^ subkey
#     substituted_data = substitute(xor_result)
#     permuted_data = permute(substituted_data, [16, 7, 20, 21, 29, 12, 28, 17,
#                                                 1, 15, 23, 26, 5, 18, 31, 10,
#                                                 2, 8, 24, 14, 32, 27, 3, 9,
#                                                 19, 13, 30, 6, 22, 11, 4, 25])

#     new_right_half = left_half ^ permuted_data
#     new_left_half = right_half

#     return new_left_half, new_right_half

# def generate_subkeys(key):
#     # Replace the following line with the actual subkey generation logic
#     subkeys = [key] * 16  # Placeholder logic, replace with DES key schedule

#     return subkeys

# def encrypt_des(block, key):
#     # Implement DES encryption for a single block
#     subkeys = generate_subkeys(key)
#     block = initial_permutation(block)

#     left_half, right_half = block >> 32, block & 0xFFFFFFFF
#     for subkey in subkeys:
#         left_half, right_half = des_round(left_half, right_half, subkey)

#     block = (right_half << 32) | left_half
#     block = final_permutation(block)

#     return block

# def decrypt_des(block, key):

#     # Implement DES decryption for a single block
#     subkeys = generate_subkeys(key)
#     block = initial_permutation(block)

#     left_half, right_half = block >> 32, block & 0xFFFFFFFF
#     for subkey in reversed(subkeys):
#         left_half, right_half = des_round(left_half, right_half, subkey)

#     block = (right_half << 32) | left_half
#     block = final_permutation(block)

#     return block

# key = 0x133457799BBCDFF1  # Replace with your key
# plaintext_block = 0x0123456789ABCDEF  # Replace with your plaintext block

# ciphertext_block = encrypt_des(plaintext_block, key)
# print(f'Ciphertext: {ciphertext_block:x}')

# decrypted_block = decrypt_des(ciphertext_block, key)
# print(f'Decrypted Block: {decrypted_block:x}')


def generate_des_key():
    return get_random_bytes(8)


def encrypt_des(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), DES.block_size))
    return ciphertext


def decrypt_des(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_message.decode("utf-8")


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


# -------------------------------------------------------------Algorithm------------------------------------------------------------------------


key_length_bits = 128


def encrypt_button_click():
    message = message_textbox.get()
    selected_val = combo_var.get()

    rc4_key = str(secrets.token_bytes(key_length_bits // 8))
    # des_key= public_key_textbox.get()
    # des_key=pad(des_key)
    if selected_val == "Single key (DES)":
        message = message_textbox.get()
    #     message=pad(message)
    #     des_key= public_key_textbox.get()
    #     des_key=pad(des_key)
    #     ciphertexts = (encrypt_des(message, des_key))
    #     ciphertext_entry.delete(0, tk.END)
    #     ciphertext_entry.insert(0, ciphertexts)
    elif selected_val == "Caesar cipher":
        shift = random.randint(1, 10)
        ciphertext = encrypt_caesar(message, shift)
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
