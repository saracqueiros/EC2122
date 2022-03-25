from logging import raiseExceptions
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class emitter:

    def __init__(self, mensagem, assinatura): 
        self.message = mensagem.encode('utf-8')
        self.signing_message = assinatura.encode('utf-8')
        self.mac = None
        self.Ed448_private_key = self.generate_Ed448_private_key()
        self.Ed448_public_key = self.generate_Ed448_public_key()
        self.signature = self.generate_Ed448_signature()

        self.X448_private_key = self.generate_X448_private_key()
        self.X448_public_key = self.generate_X448_public_key()
        self.X448_shared_key = None


    
    #“Ed448 Signing&Verification”
    def generate_Ed448_signature(self):
        return self.Ed448_private_key.sign(self.signing_message)

    def generate_Ed448_private_key(self):
        return Ed448PrivateKey.generate()
    
    def generate_Ed448_public_key(self):
        return self.Ed448_private_key.public_key()

    #“X448 key exchange” 
    def generate_X448_private_key(self):
        # Gera a private key utilizando X448
        return X448PrivateKey.generate()
    
    def generate_X448_public_key(self):
        # Gera a chave pública a partir da privada já gerada
        return self.X448_private_key.public_key()

    #Gera a chave partilhada a partir da mistura da sua privada e publica do receiver 
    def generate_X448_shared_key(self, X448_receiver_public_key):
        key = self.X448_private_key.exchange(X448_receiver_public_key)
        self.X448_shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(key)

    #Gera a chave que o receiver tem de confirmar para saber se está a receber a informação de quem pretende  
    def key_to_confirm(self):
        nonce = os.urandom(16)
        algorithm = algorithms.ChaCha20(self.X448_shared_key, nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        ciphered = encryptor.update(self.X448_shared_key)
        ciphered = nonce + ciphered
        return ciphered

    def create_authentication(self, message):
        h = hmac.HMAC(self.X448_shared_key, hashes.SHA256(), backend=default_backend())
        h.update(message)
        self.mac = h.finalize()
        
    

    def generate_tweak(self, contador, tag):
        #Um tweak é constituído por 4 bytes de nonce + 4 de contador + 1 de tag 
        #Tal como diz no capítulo 1
        nonce = os.urandom(8)
        return nonce + contador.to_bytes(7,byteorder = 'big') + tag.to_bytes(1,byteorder = 'big')

    def degenerate_tweak(self, tweak):
        nonce = tweak[0:8]
        contador = int.from_bytes(tweak[8:15], byteorder = 'big')
        tag_final = tweak[15]
        print("nonce", nonce, "contador", contador, "tag", tag_final)
        
   
    def encodeAndSend(self):
        #Guardar o tamanho da mensagem 
        size_msg = len(self.message)
        # Add padding à msg
        padder = padding.PKCS7(64).padder()
        padded = padder.update(self.message) + padder.finalize()  
        cipher_text = b''                
        contador = 0
        final = ""
        for i in range(0,len(padded),16):
            p=padded[i:i+16]
            if (i+16+1 > len(padded)):
                #Ultimo bloco com tag 1 
                tweak = self.generate_tweak(size_msg,1)
                cipher_text += tweak 
                middle = b''
                for index, byte in enumerate(p): 
                    #aplicar as máscaras XOR aos blocos  
                    mascara = self.X448_shared_key + tweak
                    middle += bytes([byte ^ mascara[0:16][0]])
                print("tamanho disto com xor ", len(middle))
                cipher_text += middle 
                
            else:
                #Blocos intermédios com tag 0
                tweak = self.generate_tweak(contador,0)
                cipher = Cipher(algorithms.AES(self.X448_shared_key), mode=modes.XTS(tweak))
                encryptor = cipher.encryptor()
                ct = encryptor.update(p)
                cipher_text += tweak + ct 
            contador += 1

        print("size:", len(cipher_text))


        self.create_authentication(cipher_text)
        final_ciphered = self.mac + cipher_text 
        return final_ciphered

           
