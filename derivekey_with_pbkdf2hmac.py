# -*-coding:utf-8 -*

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# 1. Configuration des paramètres de sécurité
mot_de_passe = b"MonMotDePasseSuperSecurise123!"
message_original = b"Ceci est un secret confidentiel"

# 2. Generation d'un sel aleatoire unique (obligatoire pour chaque opération)
sel = os.urandom(16)

print(f"\n----------Etape 1: Dérivation de la clé -------\n")
# 2. Initialisation de la fonction de dérivation (KDF-Key Derivation Function)
# On utilise PBKDF2 avec SHA-256 et 600 000 itérations (standard actuel)
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sel,
        iterations=600000
        )

# Calcul de la clé à partir du mot de passe
cle_derivee = kdf.derive(mot_de_passe)
print(f"Clé dérivée (AES-256) : {cle_derivee.hex()}")


print("\n----------Etape 2: Chiffrement -------\n")
#3. Initialisation du chiffrement AES-256 avec la clé derivé
aesgcm = AESGCM(cle_derivee)

# Génération d'un nonce(nombre a usage unique) indispensable pour AES-GCM
nonce = os.urandom(12)


# Chiffrement du message (AES-GCM authentifié )
message_chiffre = aesgcm.encrypt(nonce, message_original, None)
print(f"Message chiffré (hex) : {message_chiffre.hex()}")


print(f"\n--- ÉTAPE 3 : Déchiffrement ------\n")
# 4. Pour déchiffrer, il faut RE-DÉRIVER la clé avec le MÊME sel
kdf_dechiffrement = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=sel,               # On réutilise le sel stocké ou transmis
                    iterations=600000
                    )
                    
cle_pour_dechiffrer = kdf_dechiffrement.derive(mot_de_passe)
print(f"Clé dérivée pour dechiffrer (AES-256) : {cle_pour_dechiffrer.hex()}")

# Initialisation d'AES-GCM pour le déchiffremen
aesgcm_dechiffrement = AESGCM(cle_pour_dechiffrer)

# Déchiffrement à l'aide du nonce et des données chiffrées
# Remarque: On utilise le meme nonce que celui pour chiffrer, il doit etre stocké ou fourni
message_dechiffre = aesgcm_dechiffrement.decrypt(nonce, message_chiffre, None)
print(f"Message déchiffré : {message_dechiffre.decode('utf-8')}")