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
        self.ip_entry.insert(0, '127.0.0.1') # IP para conectar -- mudar quando for testar com dois computadores
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
        msg_original = self.msg_entry.get()
        if not msg_original:
            messagebox.showerror("Erro", "A mensagem não pode estar vazia.")
            return

        # --- ETAPA DE CRIPTOGRAFIA ---
        # T4: Criptografa a mensagem. O resultado são 3 partes em bytes.
        nonce, texto_cifrado, tag = criptografar(msg_original)

        # =================================================================
        #  NOVA LÓGICA PARA VISUALIZAÇÃO (GRÁFICO)
        # =================================================================
        # T1/T5: Converte APENAS o texto cifrado para uma string binária para o gráfico.
        binario_para_grafico = bytes_para_string_binaria(texto_cifrado)
        self.binary_text.delete(1.0, tk.END)
        self.binary_text.insert(tk.END, f"Binário do Texto Cifrado (para o gráfico):\n{binario_para_grafico}")

        # T6: Aplica o MLT-3 sobre o binário do texto cifrado.
        sinal_mlt3_para_grafico = codificar_mlt3(binario_para_grafico)
        
        # T2: Mostra o gráfico focado APENAS na mensagem cifrada.
        self.desenhar_grafico(self.ax_send, self.canvas_send, sinal_mlt3_para_grafico, "Sinal MLT-3 (Apenas Mensagem Cifrada)")
        
        # Mostra a parte criptografada (em hexadecimal) na GUI para referência
        self.crypto_text.delete(1.0, tk.END)
        self.crypto_text.insert(tk.END, f"Nonce: {nonce.hex()}\nTag: {tag.hex()}\nCifrado: {texto_cifrado.hex()}")

        # =================================================================
        #  LÓGICA PARA TRANSMISSÃO (REDE)
        # =================================================================
        # Monta o pacote COMPLETO com todos os bytes necessários para o receptor.
        pacote_completo_bytes = nonce + tag + texto_cifrado
        
        # Simula as camadas para o pacote completo, conforme requisitos do projeto.
        binario_completo_para_rede = bytes_para_string_binaria(pacote_completo_bytes)
        sinal_mlt3_completo_para_rede = codificar_mlt3(binario_completo_para_rede)

        # Prepara os dados para envio (ex: uma string de "1,0,-1,...")
        dados_para_enviar = ",".join(map(str, sinal_mlt3_completo_para_rede))

        # T7: Envia os dados completos pela rede em uma thread separada.
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
            # Recebe todos os dados enviados pela rede
            buffer_str = ""
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                buffer_str += data.decode('utf-8')
            
            # --- ETAPAS DE REVERSÃO DO PACOTE COMPLETO (HOST B) ---

            # 1. Converte a string "1,0,-1,..." de volta para uma lista de níveis de tensão
            niveis_recebidos = [int(n) for n in buffer_str.split(',')]
            
            # 2. Decodifica o sinal MLT-3 COMPLETO para a string binária COMPLETA
            binario_completo_recebido = decodificar_mlt3(niveis_recebidos)
            
            # 3. Converte a string binária COMPLETA de volta para o pacote de BYTES COMPLETO
            pacote_completo_bytes = string_binaria_para_bytes(binario_completo_recebido)

            # 4. AGORA SIM, divide (fatia) o pacote de bytes em suas partes constituintes
            # Conforme o nosso protocolo: 12 bytes de nonce, 16 de tag, e o resto de cifrado.
            nonce_recebido = pacote_completo_bytes[:12]
            tag_recebida = pacote_completo_bytes[12:28]
            cifrado_recebido = pacote_completo_bytes[28:]

            # --- VISUALIZAÇÃO E DESCRIPTOGRAFIA ---
            
            # T2: Gera o gráfico focado APENAS na parte da mensagem cifrada recebida
            # para manter a simetria com o lado do emissor.
            if cifrado_recebido: # Garante que há dados para plotar
                binario_para_grafico = bytes_para_string_binaria(cifrado_recebido)
                sinal_mlt3_para_grafico = codificar_mlt3(binario_para_grafico)
                self.desenhar_grafico(self.ax_recv, self.canvas_recv, sinal_mlt3_para_grafico, "Sinal MLT-3 Recebido (Apenas Mensagem)")

            # T8: Descriptografa usando as 3 partes corretas
            pacote_para_descriptografar = (nonce_recebido, cifrado_recebido, tag_recebida)
            msg_final = descriptografar(pacote_para_descriptografar)
            
            # Atualiza a caixa de texto da GUI com a mensagem final
            self.received_text.config(state='normal')
            self.received_text.delete(1.0, tk.END)
            self.received_text.insert(tk.END, msg_final)
            self.received_text.config(state='disabled')


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()