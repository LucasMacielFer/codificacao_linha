import socket

# Define o endereço IP e a porta
# Deixar o host como '' faz o servidor escutar em todos os IPs disponíveis
HOST = ''  # Ou o IP específico do servidor
PORTA = 65432

# Cria o socket TCP/IP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Vincula o socket ao endereço e porta
    s.bind((HOST, PORTA))
    # Começa a escutar por conexões
    s.listen()
    print(f"Servidor escutando em {socket.gethostbyname(socket.gethostname())}:{PORTA}")
    # Aceita uma nova conexão
    conn, addr = s.accept()
    with conn:
        print(f"Conectado por {addr}")
        while True:
            # Recebe dados do cliente
            dados = conn.recv(1024)
            if not dados:
                break
            # Exibe a mensagem recebida
            print(f"Mensagem recebida: {dados.decode()}")
            # Envia uma resposta de volta para o cliente (opcional)
            conn.sendall(b'Mensagem recebida com sucesso!')