# -*-coding:utf-8 -*
import os
from coffre import cle_maitresse, sous_cle, chiffrer, dechiffrer


def check_rename_file():
    
    donnee_a_chiffrer = b"Mon travail de TP en cryptographie"
    print(f"\nMessage Original contenu ds le fichier:{donnee_a_chiffrer}\n\n")
    
    data_chiffrer = chiffrer("mon Bon Password", "donnees.txt", donnee_a_chiffrer)
    print(f"\nLe Resulat du chiffrement:{data_chiffrer.hex()}\n")
    
    
    data_dechiffrer = dechiffrer("mon Bon Password", "fichiers.txt", data_chiffrer)
    
    print(f"\nLe Resulat du Déchiffrement:{data_dechiffrer}")

def check_chiffre_corrupted():
    
    donnee_a_chiffrer = b"Mon travail de TP en cryptographie"
    print(f"\nMessage Original contenu ds le fichier:{donnee_a_chiffrer}\n\n")
    
    data_chiffrer = chiffrer("mon Bon Password", "donnees.txt", donnee_a_chiffrer)
    print(f"\nLe Resulat du chiffrement:{data_chiffrer.hex()}\n")
    
    data_chiffrer_array = bytearray(data_chiffrer)
    data_chiffrer_array[45] ^= 1
    
    data_chiffrer = bytes(data_chiffrer_array)
    data_dechiffrer = dechiffrer("mon mauvais Password", "donnees.txt", data_chiffrer)
    
    print(f"\nLe Resulat du Déchiffrement:{data_dechiffrer}")

def check_wrong_password():
    
    donnee_a_chiffrer = b"Mon travail de TP en cryptographie"
    print(f"\nMessage Original contenu ds le fichier:{donnee_a_chiffrer}\n\n")
    
    data_chiffrer = chiffrer("mon Bon Password", "donnees.txt", donnee_a_chiffrer)
    print(f"\nLe Resulat du chiffrement:{data_chiffrer.hex()}\n")
    
    
    data_dechiffrer = dechiffrer("mon mauvais Password", "donnees.txt", data_chiffrer)
    
    print(f"\nLe Resulat du Déchiffrement:{data_dechiffrer}")

def check_aller_retour():
    
    donnee_a_chiffrer = b"Mon travail de TP en cryptographie"
    print(f"\nMessage Original contenu ds le fichier:{donnee_a_chiffrer}\n\n")
    
    data_chiffrer = chiffrer("monPassword", "donnees.txt", donnee_a_chiffrer)
    print(f"\nLe Resulat du chiffrement:{data_chiffrer.hex()}\n")
    
    
    data_dechiffrer = dechiffrer("monPassword", "donnees.txt", data_chiffrer)
    
    print(f"\nLe Resulat du Déchiffrement:{data_dechiffrer}")


def check_generationcle():
    
    print(f"\nMot de passe: MonSecretBienGarder\n")
    myMasterKey = cle_maitresse("MonSecretBienGarder", b"teste-mon-secret")
    print(f"La clé maitresse est:{myMasterKey.hex()}")
    
    encryptionKey = sous_cle(myMasterKey, b"test-generation")
    print(f"\nLa clé pour le chiffrement final :{encryptionKey.hex()}\n")
    
    
if __name__ == "__main__":
    #check_generationcle()
    
    #check_aller_retour()
    
    #check_wrong_password()
    
    #check_chiffre_corrupted()
    
    check_rename_file()