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
        print(message)
        if len(message.split("~")) > 2:
            if message != "":
                csr =0
                username = message.split("~")[0]
                content = message.split("~")[1]
                enctype = message.split("~")[2]
                if enctype[0] == "C" or "c":
                    csr = int(enctype[0][-1])
                if myusername[0] != username:
                    KeyPair["SessionKey"] = (
                        int(message.split("~")[3]) ** KeyPair["PrivateKey"] % 307
                    )
                PK = message.split("~")[3]
                #print(decrypt_button_click(content))
                add_message(f"[{username}] {decrypt_button_click(content,enctype,csr)}")
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
            encrypted_message = rsa_encrypt(message, KeyPair["PublicKey"])
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

# DES ALGORITHM
def hex2bin(s):
	mp = {'0': "0000",
		'1': "0001",
		'2': "0010",
		'3': "0011",
		'4': "0100",
		'5': "0101",
		'6': "0110",
		'7': "0111",
		'8': "1000",
		'9': "1001",
		'A': "1010",
		'B': "1011",
		'C': "1100",
		'D': "1101",
		'E': "1110",
		'F': "1111"}
	bin = ""
	for i in range(len(s)):
		bin = bin + mp[s[i]]
	return bin

def bin2hex(s):
	mp = {"0000": '0',
		"0001": '1',
		"0010": '2',
		"0011": '3',
		"0100": '4',
		"0101": '5',
		"0110": '6',
		"0111": '7',
		"1000": '8',
		"1001": '9',
		"1010": 'A',
		"1011": 'B',
		"1100": 'C',
		"1101": 'D',
		"1110": 'E',
		"1111": 'F'}
	hex = ""
	for i in range(0, len(s), 4):
		ch = ""
		ch = ch + s[i]
		ch = ch + s[i + 1]
		ch = ch + s[i + 2]
		ch = ch + s[i + 3]
		hex = hex + mp[ch]

	return hex

def bin2dec(binary):

	binary1 = binary
	decimal, i, n = 0, 0, 0
	while(binary != 0):
		dec = binary % 10
		decimal = decimal + dec * pow(2, i)
		binary = binary//10
		i += 1
	return decimal

def dec2bin(num):
	res = bin(num).replace("0b", "")
	if(len(res) % 4 != 0):
		div = len(res) / 4
		div = int(div)
		counter = (4 * (div + 1)) - len(res)
		for i in range(0, counter):
			res = '0' + res
	return res

def permute(k, arr, n):
	permutation = ""
	for i in range(0, n):
		permutation = permutation + k[arr[i] - 1]
	return permutation

def shift_left(k, nth_shifts):
	s = ""
	for i in range(nth_shifts):
		for j in range(1, len(k)):
			s = s + k[j]
		s = s + k[0]
		k = s
		s = ""
	return k

def xor(a, b):
	ans = ""
	for i in range(len(a)):
		if a[i] == b[i]:
			ans = ans + "0"
		else:
			ans = ans + "1"
	return ans

initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7]

exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1]

per = [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25]

sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]

def des_encrypt(pt, rkb, rk):
	pt = hex2bin(pt)

	# Initial Permutation
	pt = permute(pt, initial_perm, 64)
	print("After initial permutation", bin2hex(pt))

	# Splitting
	left = pt[0:32]
	right = pt[32:64]
	for i in range(0, 16):
		# Expansion D-box: Expanding the 32 bits data into 48 bits
		right_expanded = permute(right, exp_d, 48)

		# XOR RoundKey[i] and right_expanded
		xor_x = xor(right_expanded, rkb[i])

		# S-boxex: substituting the value from s-box table by calculating row and column
		sbox_str = ""
		for j in range(0, 8):
			row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
			col = bin2dec(
				int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
			val = sbox[j][row][col]
			sbox_str = sbox_str + dec2bin(val)

		# Straight D-box: After substituting rearranging the bits
		sbox_str = permute(sbox_str, per, 32)

		# XOR left and sbox_str
		result = xor(left, sbox_str)
		left = result

		# Swapper
		if(i != 15):
			left, right = right, left
		print("Round ", i + 1, " ", bin2hex(left),
			" ", bin2hex(right), " ", rk[i])

	# Combination
	combine = left + right

	# Final permutation: final rearranging of bits to get cipher text
	cipher_text = permute(combine, final_perm, 64)
	return cipher_text



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
    print(decrypted_message)
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


def rsa_encrypt(message, public_key):
    n, e = public_key
    encrypted_msg = [pow(ord(char), e, n) for char in message]
    return encrypted_msg


def rsa_decrypt(encrypted_msg, private_key):
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
shift = random.randint(1, 10)

def encrypt_button_click():
    message = message_textbox.get()
    selected_val = combo_var.get()
    rc4_key = str(secrets.token_bytes(key_length_bits // 8))
    if selected_val == "Single key (DES)":
        pt = message_textbox.get()
        key = prime_number_textbox.get()
        key = hex2bin(key)
        keyp = [57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4]
        key = permute(key, keyp, 56)
        shift_table = [1, 1, 2, 2,
			2, 2, 2, 2,
			1, 2, 2, 2,
			2, 2, 2, 1]
        key_comp = [14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32]
        left = key[0:28] # rkb for RoundKeys in binary
        right = key[28:56] # rk for RoundKeys in hexadecimal
        rkb = []
        rk = []
        for i in range(0, 16):
            left = shift_left(left, shift_table[i])
            right = shift_left(right, shift_table[i])
            combine_str = left + right
            round_key = permute(combine_str, key_comp, 48)
            rkb.append(round_key)
            rk.append(bin2hex(round_key))
        
        cipher_text = bin2hex(des_encrypt(pt, rkb, rk))
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, cipher_text)
        client.sendto(f"{cipher_text}~{selected_val}~{KeyPair['PublicKey']}".encode(), (HOST, PORT))
    elif selected_val == "Caesar cipher":
        ciphertext = encrypt_caesar(message, shift)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
        client.sendto(f"{ciphertext}~{selected_val}{shift}~{KeyPair['PublicKey']}".encode(), (HOST, PORT))
    elif selected_val == "Two keys (EL GAMAL)":
        ciphertext = encrypt_elgamal(message)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext)
        client.sendto(f"{ciphertext}~{selected_val}~{KeyPair['PublicKey']}".encode(), (HOST, PORT))
    elif selected_val == "Two keys (RSA)":
        encrypted_message = rsa_encrypt(message, KeyPair["PublicKey"])
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, encrypted_message)
        client.sendto(f"{encrypted_message}~{selected_val}~{KeyPair['PublicKey']}".encode(), (HOST, PORT))
    elif selected_val == "RC4":
        encrypted_result, decrypted_result = RC4_encrypt_decrypt(message, rc4_key)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, encrypted_result)
        client.sendto(f"{encrypted_result}~{selected_val}~{KeyPair['PublicKey']}".encode(), (HOST, PORT))


def decrypt_button_click(ciphertext_hex, selected_val,csr):
    rc4_key = str(secrets.token_bytes(key_length_bits // 8))
    message = ciphertext_hex
    # des_key= public_key_textbox.get()
    # des_key=pad(des_key)
    if selected_val == "Single key (DES)":
        pt = message_textbox.get()
        key = prime_number_textbox.get()
        key = hex2bin(key)
        keyp = [57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4]
        key = permute(key, keyp, 56)
        shift_table = [1, 1, 2, 2,
			2, 2, 2, 2,
			1, 2, 2, 2,
			2, 2, 2, 1]
        key_comp = [14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32]
        left = key[0:28] # rkb for RoundKeys in binary
        right = key[28:56] # rk for RoundKeys in hexadecimal
        rkb = []
        rk = []
        for i in range(0, 16):
            left = shift_left(left, shift_table[i])
            right = shift_left(right, shift_table[i])
            combine_str = left + right
            round_key = permute(combine_str, key_comp, 48)
            rkb.append(round_key)
            rk.append(bin2hex(round_key))
        cipher_text = bin2hex(des_encrypt(pt, rkb, rk))
        
        rkb_rev = rkb[::-1]
        rk_rev = rk[::-1]
        decrypted_message = bin2hex(des_encrypt(cipher_text, rkb_rev, rk_rev))
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_message)
        return decrypted_message
    elif selected_val == "Caesar cipher":
        decrypted_message = decrypt_caesar(ciphertext_hex, shift)
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_message)
        return decrypted_message
    elif selected_val == "Two keys (EL GAMAL)":
        # print(f"cipher msg Elgamal : {message}")
        decrypted_message = decrypt_elgamal(ciphertext_hex)
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_message)
        return decrypted_message
    elif selected_val == "Two keys (RSA)":
        encrypted_message = rsa_encrypt(message, KeyPair["PublicKey"])
        decrypted_message = rsa_decrypt(encrypted_message, KeyPair["PrivateKey"])
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_message)
        return decrypted_message
    elif selected_val == "RC4":
        encrypted_result, decrypted_result = RC4_encrypt_decrypt(message, rc4_key)
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted_result)
        return decrypted_result


def combined_command():
    encrypt_button_click()
    #decrypt_button_click()
    #send_message()


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


prime_number_label = tk.Label(
    bottom_frame2, text="public key:", font=FONT, bg=DARK_GREY, fg=WHITE
)
prime_number_label.pack(side=tk.LEFT, padx=10)

prime_number_textbox = tk.Entry(
    bottom_frame2, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=10
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
