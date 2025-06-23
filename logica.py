from Crypto.Cipher import ChaCha20_Poly1305

# T4 - Criptografia com ChaCha20
# IMPORTANTE: A chave para ChaCha20 DEVE ter 32 bytes.
CHAVE = b'ChaveSegura123456789012345678901'  # Exemplo de chave, deve ser mantida em segredo

def criptografar(texto_plano):
    """Criptografa e retorna as partes como bytes brutos."""
    texto_bytes = texto_plano.encode('latin-1')
    cipher = ChaCha20_Poly1305.new(key=CHAVE)
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)
    # Retorna uma tupla com os 3 componentes essenciais
    return (cipher.nonce, texto_cifrado, tag)

def descriptografar(pacote_binario):
    """Recebe as partes como bytes brutos e descriptografa."""
    (nonce, texto_cifrado, tag) = pacote_binario
    try:
        cipher = ChaCha20_Poly1305.new(key=CHAVE, nonce=nonce)
        texto_plano_bytes = cipher.decrypt_and_verify(texto_cifrado, tag)
        return texto_plano_bytes.decode('latin-1')
    except (ValueError, KeyError):
        return "ERRO: Mensagem inválida ou corrompida!"

# T5 - Transformação para Binário
def texto_para_binario(texto):
    # Usando 'latin-1' para suportar a tabela ASCII estendida
    bytes_do_texto = texto.encode('latin-1')
    return ''.join(format(byte, '08b') for byte in bytes_do_texto)

def binario_para_texto(string_binaria):
    bytes_do_texto = bytearray()
    for i in range(0, len(string_binaria), 8):
        byte = string_binaria[i:i+8]
        bytes_do_texto.append(int(byte, 2))
    return bytes_do_texto.decode('latin-1')

# T6 - Codificação de Linha MLT-3
def codificar_mlt3(binario_str):
    niveis = []
    nivel_atual = 0
    ultimo_nivel_nao_zero = -1
    for bit in binario_str:
        if bit == '1':
            if nivel_atual == 0:
                nivel_atual = -ultimo_nivel_nao_zero
                ultimo_nivel_nao_zero = nivel_atual
            else:
                nivel_atual = 0
        niveis.append(nivel_atual)
    return niveis

# T8 - Decodificação de Linha MLT-3
def decodificar_mlt3(lista_de_niveis):
    string_binaria = ""
    nivel_anterior = 0
    for nivel in lista_de_niveis:
        if nivel == nivel_anterior:
            string_binaria += '0'
        else:
            string_binaria += '1'
        nivel_anterior = nivel
    return string_binaria


def bytes_para_string_binaria(bytes_obj):
    """Converte um objeto de bytes diretamente para uma string de '0's e '1's."""
    return ''.join(format(byte, '08b') for byte in bytes_obj)

def string_binaria_para_bytes(string_binaria):
    """Converte uma string de '0's e '1's de volta para um objeto de bytes."""
    # Garante que a string tenha um comprimento múltiplo de 8, se necessário
    padding = '0' * (8 - len(string_binaria) % 8) if len(string_binaria) % 8 != 0 else ''
    string_binaria_padded = padding + string_binaria
    
    b = bytearray()
    for i in range(0, len(string_binaria_padded), 8):
        byte = string_binaria_padded[i:i+8]
        b.append(int(byte, 2))
    return bytes(b)

# --- Bloco de Teste ---
if __name__ == '__main__':
    # Este bloco só executa quando você roda 'python logica.py' diretamente
    print("--- INICIANDO TESTE DE LÓGICA ---")