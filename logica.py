from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import json

# T4 - Criptografia com ChaCha20
# IMPORTANTE: A chave para ChaCha20 DEVE ter 32 bytes.
CHAVE = b'ChaveSegura123456789012345678901'  # Exemplo de chave, deve ser mantida em segredo

def criptografar(texto_plano):
    """Criptografa usando ChaCha20-Poly1305, que não requer padding."""
    texto_bytes = texto_plano.encode('latin-1')
    
    # Cria um novo objeto de cifra. Um 'nonce' (número usado uma vez) é gerado automaticamente.
    cipher = ChaCha20_Poly1305.new(key=CHAVE)
    
    # Criptografa e gera uma "tag" de autenticação ao mesmo tempo.
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)
    
    # O receptor precisará do nonce, do texto cifrado e da tag para descriptografar e verificar.
    # Empacotamos tudo em um dicionário.
    return {
        'nonce': cipher.nonce.hex(),
        'texto_cifrado': texto_cifrado.hex(),
        'tag': tag.hex()
    }

def descriptografar(pacote_cifrado):
    """Descriptografa e VERIFICA a autenticidade usando ChaCha20-Poly1305."""
    try:
        # Desempacota os dados recebidos, convertendo de hexadecimal para bytes.
        nonce = bytes.fromhex(pacote_cifrado['nonce'])
        texto_cifrado = bytes.fromhex(pacote_cifrado['texto_cifrado'])
        tag = bytes.fromhex(pacote_cifrado['tag'])
        
        # Cria o objeto de cifra com a mesma chave e o mesmo nonce da criptografia.
        cipher = ChaCha20_Poly1305.new(key=CHAVE, nonce=nonce)
        
        # Tenta descriptografar E verificar. Se a 'tag' não corresponder
        # (ou seja, se a mensagem foi alterada), esta linha levantará um ValueError.
        texto_plano_bytes = cipher.decrypt_and_verify(texto_cifrado, tag)
        
        return texto_plano_bytes.decode('latin-1')

    except (ValueError, KeyError):
        # Se a verificação falhar ou os dados estiverem corrompidos, retorna uma mensagem de erro.
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

# --- Bloco de Teste ---
if __name__ == '__main__':
    # Este bloco só executa quando você roda 'python logica.py' diretamente
    print("--- INICIANDO TESTE DE LÓGICA ---")

    # Sequência do Host A
    mensagem_original = "Teste com acentuação e ç!"
    print(f"1. Mensagem Original: {mensagem_original}")

    pacote_cifrado = criptografar(mensagem_original)
    print(f"2. Pacote Cifrado (JSON): {pacote_cifrado}")

    # Convertendo o pacote inteiro para uma string para enviar pela rede
    string_para_enviar = json.dumps(pacote_cifrado)

    binario = texto_para_binario(string_para_enviar)
    print(f"3. Em Binário: {binario[:64]}...") # Mostra só o começo

    sinal_mlt3 = codificar_mlt3(binario)
    print(f"4. Sinal MLT-3: {sinal_mlt3[:30]}...")

    print("\n--- INICIANDO PROCESSO INVERSO (HOST B) ---")

    # Sequência do Host B
    binario_recebido = decodificar_mlt3(sinal_mlt3)
    print("5. Binário Recuperado: OK" if binario_recebido == binario else "5. Binário Recuperado: FALHOU")

    string_recebida = binario_para_texto(binario_recebido)
    print("6. String (JSON) Recuperada: OK" if string_recebida == string_para_enviar else "6. String Recuperada: FALHOU")

    pacote_recebido = json.loads(string_recebida)

    mensagem_final = descriptografar(pacote_recebido)
    print(f"7. Mensagem Final: {mensagem_final}")

    print("\n--- TESTE FINALIZADO ---")
    assert mensagem_original == mensagem_final