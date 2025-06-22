import socket

HOST = '0.0.0.0' # Aceita conexões de qualquer IP na rede
PORTA = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORTA))
    s.listen()
    print(f"Servidor escutando em {HOST}:{PORTA}")
    conn, addr = s.accept()
    with conn:
        print(f"Conectado por {addr}")
        while True:
            data = conn.recv(1024) # Recebe dados
            if not data:
                break
            print(f"Recebido: {data.decode('utf-8')}")
            conn.sendall(b'Mensagem recebida!')