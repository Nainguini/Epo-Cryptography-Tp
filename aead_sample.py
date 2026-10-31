# -*-coding:utf-8 -*

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Generation d'une clé secrète de 256bits(32 octets)
cle = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(cle)

# 2. Les données a traiter
message = b"Message ultra confidentiel a chiffrer"
donnees_associees = b"ID_Context: Session_12345" #non chiffré, mais authentifié

# 3. Generation d'un nonce(Number used ONCE) - Unique pour chaque message
nonce = os.urandom(12)

# ----------------------------------------------------
# CHIFFREMENT
# ----------------------------------------------------

texte_chiffre = aesgcm.encrypt(nonce, message, donnees_associees)

print (f"Texte chiffré (hexa) : {texte_chiffre.hex()}")

# ----------------------------------------------------
# DÉCHIFFREMENT
# ----------------------------------------------------

try:
    # Si le texte chiffré OU les données associées ont été modifiés, cela lèvera une erreur
    message_dechiffre = aesgcm.decrypt(nonce, texte_chiffre, donnees_associees)
    print (f"Message déchiffrer : {message_dechiffre.decode("utf-8")}")
except Exception as e:
    print("Échec de l'authentification : Les données ont été corrompues ou modifiées !")
    