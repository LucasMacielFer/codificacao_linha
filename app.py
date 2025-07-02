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
        self.criptografia = True

        # =================================================================
        #  <<< INÍCIO DA MODIFICAÇÃO PARA ADICIONAR SCROLL >>>
        # =================================================================
        # 1. Cria um container principal para o canvas e a scrollbar
        container = tk.Frame(root)
        container.pack(fill=tk.BOTH, expand=True)

        # 2. Cria o Canvas e a Scrollbar
        canvas = tk.Canvas(container)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        
        # 3. Cria o Frame que vai conter todo o conteúdo e será rolável
        scrollable_frame = tk.Frame(canvas)

        # 4. Configura o binding para que a scrollbar saiba o tamanho do conteúdo
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        # 5. Adiciona o frame rolável dentro do canvas
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # 6. Empacota o canvas e a scrollbar no container
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        # =================================================================
        #  <<< FIM DA MODIFICAÇÃO PARA ADICIONAR SCROLL >>>
        # =================================================================


        # --- Frames para organização ---
        # MODIFICADO: O main_frame agora é filho do scrollable_frame
        main_frame = tk.Frame(scrollable_frame) 
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

        self.cripto_button = tk.Button(left_frame, text="CRIPTOGRAFIA ON", bg="green", fg="white", command=self.ativa_criptografia)
        self.cripto_button.pack(pady=10)

        tk.Label(left_frame, text="Mensagem Criptografada:").pack(anchor="w")
        self.crypto_text = scrolledtext.ScrolledText(left_frame, height=4, width=50)
        self.crypto_text.pack(fill=tk.X, expand=True)

        tk.Label(left_frame, text="Representação em Binário (Envio):").pack(anchor="w")
        self.binary_text = scrolledtext.ScrolledText(left_frame, height=4, width=50)
        self.binary_text.pack(fill=tk.X, expand=True)

        # Gráfico do Sinal Binário (antes da codificação)
        self.fig_send_bin = Figure(figsize=(5, 2.5), dpi=100)
        self.ax_send_bin = self.fig_send_bin.add_subplot(111)
        self.canvas_send_bin = FigureCanvasTkAgg(self.fig_send_bin, master=left_frame)
        self.canvas_send_bin.get_tk_widget().pack(fill=tk.BOTH, expand=True, pady=(10,0))

        # Gráfico de Envio MLT-3
        self.fig_send = Figure(figsize=(5, 2.5), dpi=100)
        self.ax_send = self.fig_send.add_subplot(111)
        self.canvas_send = FigureCanvasTkAgg(self.fig_send, master=left_frame)
        self.canvas_send.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # --- Coluna da Direita (Recepção - Host B) ---
        tk.Label(right_frame, text="RECEPÇÃO (HOST B)", font=("Helvetica", 14, "bold")).pack(pady=5)

        tk.Label(right_frame, text="Dados Brutos Recebidos (Antes de Descriptografar):").pack(anchor="w")
        self.raw_received_text = scrolledtext.ScrolledText(right_frame, height=4, width=50, state='disabled')
        self.raw_received_text.pack(fill=tk.X, expand=True)

        tk.Label(right_frame, text="Representação em Binário (Recebido):").pack(anchor="w")
        self.received_binary_text = scrolledtext.ScrolledText(right_frame, height=4, width=50, state='disabled')
        self.received_binary_text.pack(fill=tk.X, expand=True)

        tk.Label(right_frame, text="Mensagem Recebida (Final):").pack(anchor="w")
        self.received_text = scrolledtext.ScrolledText(right_frame, height=4, width=50, state='disabled')
        self.received_text.pack(fill=tk.X, expand=True)

        # Gráfico de Recepção MLT-3
        self.fig_recv = Figure(figsize=(5, 2.5), dpi=100)
        self.ax_recv = self.fig_recv.add_subplot(111)
        self.canvas_recv = FigureCanvasTkAgg(self.fig_recv, master=right_frame)
        self.canvas_recv.get_tk_widget().pack(fill=tk.BOTH, expand=True, pady=(10,0))

        # Gráfico do Sinal Binário (após a decodificação)
        self.fig_recv_bin = Figure(figsize=(5, 2.5), dpi=100)
        self.ax_recv_bin = self.fig_recv_bin.add_subplot(111)
        self.canvas_recv_bin = FigureCanvasTkAgg(self.fig_recv_bin, master=right_frame)
        self.canvas_recv_bin.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # --- Configuração de Rede ---
        self.ip_entry = tk.Entry(left_frame)
        self.ip_entry.insert(0, '127.0.0.1')
        self.ip_entry.pack(side=tk.LEFT, padx=5)

        server_thread = threading.Thread(target=self.iniciar_servidor, daemon=True)
        server_thread.start()

    def ativa_criptografia(self):
        self.criptografia = not self.criptografia
        if self.criptografia:
            self.cripto_button.config(bg="green", text="CRIPTOGRAFIA ON")
        else:
            self.cripto_button.config(bg="red", text="CRIPTOGRAFIA OFF")

    def desenhar_grafico_binario(self, ax, canvas, binario_str, titulo):
        ax.clear()

        if not binario_str:
            ax.set_title(titulo)
            canvas.draw()
            return

        niveis = [int(bit) for bit in binario_str]
        ax.step(range(len(niveis)), niveis, where='post', color='red')

        for i, nivel in enumerate(niveis):
            x_pos = i + 0.5
            y_pos = nivel + 0.15 if nivel == 0 else nivel - 0.2
            ax.text(x_pos, y_pos, str(nivel), color='black', ha='center', va='center', fontsize=8)

        ax.set_title(titulo)
        ax.set_ylabel("Nível")
        ax.set_xlabel("Bit")
        ax.set_ylim(-0.4, 1.4)
        ax.set_yticks([0, 1])
        ax.grid(True)
        canvas.figure.tight_layout()
        canvas.draw()

    def desenhar_grafico(self, ax, canvas, niveis, titulo):
        ax.clear()
        ax.step(range(len(niveis)), niveis, where='post', color='dodgerblue')

        for i, nivel in enumerate(niveis):
            x_pos = i + 0.5
            if nivel == 0:
                y_pos = nivel + 0.15
            elif nivel > 0:
                y_pos = nivel - 0.2
            else:
                y_pos = nivel + 0.15
            ax.text(x_pos, y_pos, str(nivel), color='black', ha='center', va='center', fontsize=8)

        ax.set_title(titulo)
        ax.set_ylabel("Nível")
        ax.set_xlabel("Bit")
        ax.set_ylim(-1.4, 1.4)
        ax.set_yticks([-1, 0, 1])
        ax.grid(True)
        canvas.figure.tight_layout()
        canvas.draw()
            
    def processar_e_enviar(self):
        msg_original = self.msg_entry.get()
        if not msg_original:
            messagebox.showerror("Erro", "A mensagem não pode estar vazia.")
            return

        self.crypto_text.delete(1.0, tk.END)
        self.binary_text.delete(1.0, tk.END)

        if self.criptografia:
            nonce, texto_cifrado, tag = criptografar(msg_original)
            flag_cripto = b'\x01'
            payload = nonce + tag + texto_cifrado
            self.crypto_text.insert(tk.END, f"Nonce: {nonce.hex()}\nTag: {tag.hex()}\nCifrado: {texto_cifrado.hex()}")
            dados_para_grafico = texto_cifrado
            titulo_grafico = "Sinal MLT-3 (Mensagem Cifrada)"
            titulo_grafico_bin = "Sinal Binário Original (Cifrado)"
        else:
            flag_cripto = b'\x00'
            payload = msg_original.encode('utf-8')
            self.crypto_text.insert(tk.END, "A mensagem não foi criptografada.")
            dados_para_grafico = payload
            titulo_grafico = "Sinal MLT-3 (Texto Puro)"
            titulo_grafico_bin = "Sinal Binário Original (Texto Puro)"

        pacote_completo_bytes = flag_cripto + payload

        binario_para_grafico = bytes_para_string_binaria(dados_para_grafico)
        self.binary_text.insert(tk.END, binario_para_grafico)

        self.desenhar_grafico_binario(self.ax_send_bin, self.canvas_send_bin, binario_para_grafico, titulo_grafico_bin)

        sinal_mlt3_para_grafico = codificar_mlt3(binario_para_grafico)
        self.desenhar_grafico(self.ax_send, self.canvas_send, sinal_mlt3_para_grafico, titulo_grafico)

        binario_completo_para_rede = bytes_para_string_binaria(pacote_completo_bytes)
        sinal_mlt3_completo_para_rede = codificar_mlt3(binario_completo_para_rede)
        dados_para_enviar = ",".join(map(str, sinal_mlt3_completo_para_rede))

        client_thread = threading.Thread(target=self.enviar_dados, args=(dados_para_enviar,))
        client_thread.start()


    def enviar_dados(self, dados):
        ip_destino = self.ip_entry.get()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip_destino, 65432))
                s.sendall(dados.encode('utf-8'))
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
                handler_thread = threading.Thread(target=self.manipular_conexao, args=(conn, addr), daemon=True)
                handler_thread.start()

    def manipular_conexao(self, conn, addr):
        with conn:
            buffer_str = ""
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buffer_str += data.decode('utf-8')

            if not buffer_str:
                return

            niveis_recebidos = [int(n) for n in buffer_str.split(',')]
            binario_completo_recebido = decodificar_mlt3(niveis_recebidos)
            pacote_completo_bytes = string_binaria_para_bytes(binario_completo_recebido)

            flag_cripto = pacote_completo_bytes[0:1]
            payload = pacote_completo_bytes[1:]

            msg_final = ""
            dados_para_grafico = b''
            titulo_grafico = "Sinal Recebido Inválido"
            titulo_grafico_bin = "Sinal Binário Inválido"
            raw_text_display = ""
            binario_para_grafico = ""

            if flag_cripto == b'\x01':
                try:
                    nonce_recebido = payload[:12]
                    tag_recebida = payload[12:28]
                    cifrado_recebido = payload[28:]
                    raw_text_display = f"Nonce: {nonce_recebido.hex()}\nTag: {tag_recebida.hex()}\nCifrado: {cifrado_recebido.hex()}"
                    pacote_para_descriptografar = (nonce_recebido, cifrado_recebido, tag_recebida)
                    msg_final = descriptografar(pacote_para_descriptografar)
                    dados_para_grafico = cifrado_recebido
                    titulo_grafico = "Sinal MLT-3 Recebido (Cifrado)"
                    titulo_grafico_bin = "Sinal Binário Decodificado (Cifrado)"
                except Exception as e:
                    msg_final = f"ERRO AO DESCRIPTOGRAFAR: {e}"
                    raw_text_display = "ERRO: Falha ao processar pacote criptografado."
            elif flag_cripto == b'\x00':
                msg_final = payload.decode('utf-8')
                dados_para_grafico = payload
                raw_text_display = "Mensagem sem criptografia"
                titulo_grafico = "Sinal MLT-3 Recebido (Texto Puro)"
                titulo_grafico_bin = "Sinal Binário Decodificado (Texto Puro)"
            else:
                msg_final = "ERRO: Flag de criptografia desconhecida recebida."
                raw_text_display = "ERRO: Flag de criptografia desconhecida."

            if dados_para_grafico:
                binario_para_grafico = bytes_para_string_binaria(dados_para_grafico)
                sinal_mlt3_para_grafico = codificar_mlt3(binario_para_grafico)
                self.desenhar_grafico(self.ax_recv, self.canvas_recv, sinal_mlt3_para_grafico, titulo_grafico)
                self.desenhar_grafico_binario(self.ax_recv_bin, self.canvas_recv_bin, binario_para_grafico, titulo_grafico_bin)

            self.raw_received_text.config(state='normal')
            self.raw_received_text.delete(1.0, tk.END)
            self.raw_received_text.insert(tk.END, raw_text_display)
            self.raw_received_text.config(state='disabled')
            
            self.received_binary_text.config(state='normal')
            self.received_binary_text.delete(1.0, tk.END)
            self.received_binary_text.insert(tk.END, binario_para_grafico)
            self.received_binary_text.config(state='disabled')

            self.received_text.config(state='normal')
            self.received_text.delete(1.0, tk.END)
            self.received_text.insert(tk.END, msg_final)
            self.received_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()