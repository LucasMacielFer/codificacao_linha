import socket

# O endereço IP e a porta do servidor
HOST = '192.168.1.10'  # Substitua pelo endereço IP do servidor
PORTA = 65432

# Cria o socket TCP/IP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Conecta ao servidor
    s.connect((HOST, PORTA))
    # Envia uma mensagem para o servidor
    mensagem = input("Digite a mensagem a ser enviada: ")
    s.sendall(mensagem.encode())
    # Espera por uma resposta (opcional)
    dados = s.recv(1024)

print(f"Resposta do servidor: {dados.decode()}")
