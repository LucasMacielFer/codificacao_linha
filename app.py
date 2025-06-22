# aplicativo.py
import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import json

# Importa toda a nossa lógica do outro arquivo
from logica import *

# Para o gráfico
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Comunicador com MLT-3 e Criptografia")

        # --- Frames para organização ---
        main_frame = tk.Frame(root)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        # --- Coluna da Esquerda (Envio - Host A) ---
        tk.Label(left_frame, text="ENVIO (HOST A)", font=("Helvetica", 14, "bold")).pack(pady=5)

        tk.Label(left_frame, text="Digite a Mensagem:").pack(anchor="w")
        self.msg_entry = tk.Entry(left_frame, width=50)
        self.msg_entry.pack(fill=tk.X, expand=True)

        self.send_button = tk.Button(left_frame, text="Enviar Mensagem", command=self.processar_e_enviar)
        self.send_button.pack(pady=10)

        tk.Label(left_frame, text="Mensagem Criptografada (JSON):").pack(anchor="w")
        self.crypto_text = scrolledtext.ScrolledText(left_frame, height=4, width=50)
        self.crypto_text.pack(fill=tk.X, expand=True)

        tk.Label(left_frame, text="Representação em Binário:").pack(anchor="w")
        self.binary_text = scrolledtext.ScrolledText(left_frame, height=4, width=50)
        self.binary_text.pack(fill=tk.X, expand=True)
        
        # Gráfico de Envio
        self.fig_send = Figure(figsize=(5, 2), dpi=100)
        self.ax_send = self.fig_send.add_subplot(111)
        self.canvas_send = FigureCanvasTkAgg(self.fig_send, master=left_frame)
        self.canvas_send.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # --- Coluna da Direita (Recepção - Host B) ---
        tk.Label(right_frame, text="RECEPÇÃO (HOST B)", font=("Helvetica", 14, "bold")).pack(pady=5)

        tk.Label(right_frame, text="Mensagem Recebida:").pack(anchor="w")
        self.received_text = scrolledtext.ScrolledText(right_frame, height=4, width=50, state='disabled')
        self.received_text.pack(fill=tk.X, expand=True)
        
        # Gráfico de Recepção
        self.fig_recv = Figure(figsize=(5, 2), dpi=100)
        self.ax_recv = self.fig_recv.add_subplot(111)
        self.canvas_recv = FigureCanvasTkAgg(self.fig_recv, master=right_frame)
        self.canvas_recv.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # --- Configuração de Rede ---
        self.ip_entry = tk.Entry(left_frame)
        self.ip_entry.insert(0, '127.0.0.1') # IP para conectar
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        # Iniciar o servidor em uma thread separada para não travar a GUI
        server_thread = threading.Thread(target=self.iniciar_servidor, daemon=True)
        server_thread.start()

    def desenhar_grafico(self, ax, canvas, niveis, titulo):
        ax.clear()
        # Desenha em formato de escada (onda quadrada)
        ax.step(range(len(niveis) + 1), [niveis[0]] + niveis, where='pre')
        ax.set_title(titulo)
        ax.set_ylabel("Nível")
        ax.set_xlabel("Bit")
        ax.set_ylim(-1.2, 1.2)
        ax.grid(True)
        canvas.draw()
        
    def processar_e_enviar(self):
        # Pega a mensagem da caixa de entrada
        msg_original = self.msg_entry.get()
        if not msg_original:
            messagebox.showerror("Erro", "A mensagem não pode estar vazia.")
            return

        # ---- Processo do Host A ----
        # T4: Criptografar
        pacote_cifrado = criptografar(msg_original)
        string_json = json.dumps(pacote_cifrado)
        self.crypto_text.delete(1.0, tk.END)
        self.crypto_text.insert(tk.END, string_json)
        
        # T5: Transformar em binário
        binario = texto_para_binario(string_json)
        self.binary_text.delete(1.0, tk.END)
        self.binary_text.insert(tk.END, binario)
        
        # T6: Aplicar MLT-3
        sinal_mlt3 = codificar_mlt3(binario)
        
        # T2: Mostrar o gráfico de envio
        self.desenhar_grafico(self.ax_send, self.canvas_send, sinal_mlt3, "Sinal MLT-3 Enviado")
        
        # T7: Enviar pela rede
        # Converte a lista de níveis para uma string para envio
        dados_para_enviar = ",".join(map(str, sinal_mlt3))
        client_thread = threading.Thread(target=self.enviar_dados, args=(dados_para_enviar,))
        client_thread.start()

    def enviar_dados(self, dados):
        ip_destino = self.ip_entry.get()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip_destino, 65432))
                s.sendall(dados.encode('utf-8'))
            messagebox.showinfo("Sucesso", "Mensagem enviada com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro de Conexão", f"Não foi possível conectar a {ip_destino}:\n{e}")

    def iniciar_servidor(self):
        host = '0.0.0.0'
        port = 65432
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            while True:
                conn, addr = s.accept()
                # Thread para cada cliente, para o servidor continuar escutando
                handler_thread = threading.Thread(target=self.manipular_conexao, args=(conn, addr), daemon=True)
                handler_thread.start()

    def manipular_conexao(self, conn, addr):
        with conn:
            buffer = ""
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data.decode('utf-8')
            
            # --- Processo do Host B ---
            # Recebe a string de níveis e converte de volta para lista de inteiros
            niveis_recebidos = [int(n) for n in buffer.split(',')]
            
            # T2: Mostrar gráfico do sinal recebido
            self.desenhar_grafico(self.ax_recv, self.canvas_recv, niveis_recebidos, "Sinal MLT-3 Recebido")
            
            # T8: Realizar o processo inverso
            binario_recebido = decodificar_mlt3(niveis_recebidos)
            string_json_recebida = binario_para_texto(binario_recebido)
            pacote_recebido = json.loads(string_json_recebida)
            msg_final = descriptografar(pacote_recebido)
            
            # Atualiza a caixa de texto da GUI
            self.received_text.config(state='normal')
            self.received_text.delete(1.0, tk.END)
            self.received_text.insert(tk.END, msg_final)
            self.received_text.config(state='disabled')


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()