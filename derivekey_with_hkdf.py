# -*-coding:utf-8 -*

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

 # 1. Materiau initial
input_key_material = b"SecretMaitreTresSecretETAssezLong123"
 
 # 2. Le sel(Salt):Une valeur aléatoire non secrète (fortement recommandé)
 #En production il faut stocké ou transmettre ce sel à coté du message chiffré
sel = os.urandom(16) #16 octets
 
 # 3. Dérivation de la clé chiffrement (AES-256 requiert 32 octets)
 
hkdf_cipher = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=sel,
            info=b"application-encryption-key"
            )
            
cle_derivee_cipher = hkdf_cipher.derive(input_key_material)

# 4. Dérivation d'une clé d'authentification distincte (HMAC-SHA256 requiert 32 octets)
# On change simplement le paramètre 'info' pour garantir l'étanchéité des clés.

hkdf_mac = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=sel,
            info=b"application-authentification-key"
            )

#C'est juste une autre clé derivé utilisant un parametre "info" different du premier        
cle_derivee_mac = hkdf_mac.derive(input_key_material)

# Affichage des résultats (en hexadécimal pour la lisibilité)

print(f"Sel utilisé (Hex) : {sel.hex()}")
print(f"Clé de chiffrement (Hex) : {cle_derivee_cipher.hex()}")
print(f"Clé MAC (Hex) : {cle_derivee_mac.hex()}")