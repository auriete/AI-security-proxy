import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 9091
           ))
print("Connected to proxy log server.")

buffer = ""

while True:
    data = s.recv(1024).decode("utf-8")
    if not data:
        print("Server disconnected.")
        break
    
    buffer += data
    
    # Check if a complete message has arrived
    while "<END_OF_MSG>" in buffer:
        msg, buffer = buffer.split("<END_OF_MSG>", 1)
        if len(msg.strip()) > 0:
            print(msg)