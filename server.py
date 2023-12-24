import socket
import threading
import time

HOST = "192.168.100.11"
PORT = 5555
LISTENER_LIMIT = 5
active_clients = []
active_clients = []


def listen_for_messages(client, username):
    while 1:
        message = client.recv(2048).decode("utf-8")
        if message != "":
            final_msg = username + "~" + message
            send_messages_to_all(final_msg)
        else:
            print(f"The message send from client {username} is empty")


def send_message_to_client(client, message):
    client.sendall(message.encode())


def send_messages_to_all(message):
    for user in active_clients:
        send_message_to_client(user[1], message)


def SendPublicKeyToClient(client, username, UserPK):
    while True:
        time.sleep(2)
        for i in range(len(active_clients)):
            message = active_clients[i][0] + "~" + active_clients[i][2]
            client.sendall(message.encode())


def client_handler(client):
    while 1:
        message = client.recv(2048).decode("utf-8")
        username = message.split("~")[0]
        UserPK = message.split("~")[1]
        if username != "":
            active_clients.append((username, client, UserPK))
            break
        else:
            print("Client username is empty")
    threading.Thread(
        target=listen_for_messages,
        args=(
            client,
            username,
        ),
    ).start()
    threading.Thread(
        target=SendPublicKeyToClient,
        args=(
            client,
            username,
            UserPK,
        ),
    ).start()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST} {PORT}")
    except:
        print(f"Unable to bind to host {HOST} and port {PORT}")

    server.listen(LISTENER_LIMIT)

    while 1:
        client, address = server.accept()
        print(f"Successfully connected to client {address[0]} {address[1]}")
        threading.Thread(target=client_handler, args=(client,)).start()


if __name__ == "__main__":
    main()
