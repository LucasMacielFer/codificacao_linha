import socket

HOST = '127.0.0.1' # IP DO SERVIDOR! Troque por '192.168.x.x' para testar em outra máquina.
PORTA = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORTA))
    s.sendall(b'Ola, mundo!')
    data = s.recv(1024)

print(f"Resposta do servidor: {data.decode('utf-8')}")