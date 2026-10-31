# -*-coding:utf-8 -*
import os
import time
from coffre import cle_maitresse

#Global parameters for Argon2id
#T, M, P = 3, 64 * 1024, 4 
T, M, P = 5, 256 * 1024 , 8

print("Début de la dérivation Argon2id...")
start_counter = time.perf_counter()

# Génération du hash
myMasterKey = cle_maitresse("MonSecretBienGarder", b"teste-mon-secret")

end_counter = time.perf_counter()
temps = end_counter - start_counter

print(f"Chiffrement réussi en : {temps:.4f} secondes\n")
print(f"Mot de passe: MonSecretBienGarder\n")
print(f"La clé maitresse est: {myMasterKey.hex()}")

