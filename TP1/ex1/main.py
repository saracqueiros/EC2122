from emitter import emitter
from receiver import receiver 
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

def create_tweakable(key):
    tweakable_nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, tweakable_nonce), mode=None)
    ct = cipher.encryptor()
    tweak = ct.update(b"Tweakable")
    return tweak


assinatura = input("Introduz a assinatura a utilizar:")
mensagem = input("Introduz a mensagem a cifrar:")
emitter = emitter(mensagem, assinatura)
receiver = receiver(assinatura)

#Autenticacao dos agentes
receiver.verify_Ed448_signature(emitter.signature, emitter.Ed448_public_key)

#Setup do Key exchange (X448)
emitter.generate_X448_shared_key(receiver.X448_public_key)
receiver.generate_X448_shared_key(emitter.X448_public_key)

# Verificar se as chaves foram bem acordadas
key_ciphertext = emitter.key_to_confirm()
receiver.confirm_key(key_ciphertext)



#Envio da mensagem cifrada e a respetiva decifragem dela 
ciphertext = emitter.encodeAndSend()
plaintext = receiver.receiveAndDecode(ciphertext)
print("Mensagem Decifrada: \n" , plaintext)


