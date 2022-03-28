from logging import raiseExceptions
from pydoc import plain
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class receiver:
    def __init__(self, assinatura):
        self.X448_private_key = self.generate_X448_private_key()
        self.X448_public_key = self.generate_X448_public_key()
        self.X448_shared_key = None
        self.tweakable = None
        self.signing_message = assinatura.encode('utf-8')

    #Verificar se as assinaturas batem certo entre si  
    def verify_Ed448_signature(self, signature, public_key):
            try:
                public_key.verify(signature, self.signing_message)
            except: #InvalidSignature:
                raiseExceptions("Autenticação dos agentes falhou!")


    def generate_X448_private_key(self):
        # Generate a private key for use in the exchange.
        return X448PrivateKey.generate()
    
    def generate_X448_public_key(self):
        return self.X448_private_key.public_key()

    def generate_X448_shared_key(self, X448_emitter_public_key):
        key = self.X448_private_key.exchange(X448_emitter_public_key)
        self.X448_shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(key)


    ##Gestão de tweaks e criação da chave final a partir disso 
    def handle_tweak(self, tweak):
        self.tweakable = tweak
        self.final_key = self.X448_shared_key + self.tweakable


    

    def confirm_key(self, cpht):
        #16 bytes reservados para o nonce
        nonce = cpht[0:16]
        #o restante do texto cifrado corresponde à key 
        key = cpht[16:]
        #Utilização do Chacha20
        algorithm = algorithms.ChaCha20(self.X448_shared_key, nonce)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        d_key = decryptor.update(key)
        if d_key == self.X448_shared_key:
            print("\nChaves acordadas com sucesso!\n")
        else:
            raiseExceptions("Erro na verificacao das chaves acordadas")

    #verifica se a assinatura que vem no texto cifrado corresponde ao que ele espera 
    # de acordo com a chave acordada com os tweaks
    def verify_authenticate_message(self, mac_signature, ciphertext):
        h = hmac.HMAC(self.X448_shared_key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        h.verify(mac_signature)


    def degenerate_tweak(self, tweak):
        nonce = tweak[0:8]
        contador = int.from_bytes(tweak[8:15], byteorder = 'big')
        tag_final = tweak[15]
        return nonce, contador, tag_final


    def receiveAndDecode(self, ctt):
        mac = ctt[0:32]
        ct = ctt[32:]
        try:
            #Verificar se a mensagem mac enviada corresponde ao esperado
            self.verify_authenticate_message(mac, ct)
        except:
            raiseExceptions("Autenticação com falhas!")
            return
        #Se correponder, temos de a decifrar da mesma forma que foi cifrada:
        plaintext = b''
        f = b''

        #no total: bloco + tweak corresponde a corresponde a 32 bytes.
        tweak = ct[0:16]
        block = ct[16:32]
        i = 1
        _, contador, tag_final = self.degenerate_tweak(tweak)
        while(tag_final!=1):
            cipher = Cipher(algorithms.AES(self.X448_shared_key), mode=modes.XTS(tweak))
            decryptor = cipher.decryptor()
            f = decryptor.update(block) 
            plaintext += f
            tweak = ct[i*32:i*32 +16]  
            block = ct[i*32 +16:(i+1)*32]
            _, contador, tag_final = self.degenerate_tweak(tweak)
            i+= 1
        if (tag_final == 1):
            c =b''
            for index, byte in enumerate(block): 
                #aplicar as máscaras XOR aos blocos  
                mascara = self.X448_shared_key + tweak
                c += bytes([byte ^ mascara[0:16][0]])
            plaintext += c       

        unpadder = padding.PKCS7(64).unpadder()
        unpadded_message = unpadder.update(plaintext) + unpadder.finalize()

        if (len(unpadded_message.decode("utf-8")) == contador):
            print("Tweak de autenticação validado!")
            return unpadded_message.decode("utf-8")
        else: raiseExceptions("Tweak de autenticação inválido")
         
