# -*-coding:utf-8 -*
import os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


#Global parameters for Argon2id
T, M, P = 3, 64 * 1024, 4 

""" ----------------------------------------------------
	Fonction cle_maitresse
	Utilisation de Argon2i pour hasher le mot de passe passé en parametre
	l'empreinte produit doit avoir un taille de  32 octets
	# Parametres en entré de la function @Param 1 = mot_de_passe, @Param2 = salt
	LA fonction return un resultat en bytes qui represente la clé maitresse
	----------------------------------------------------
"""
def cle_maitresse(mot_de_passe: str, salt:bytes) -> bytes: 

	# 1. Convertir le mot de passe en entré en bytes
	raw_password = bytes(mot_de_passe, "utf-8") 
	
	# 2. Le sel
	sel = salt
	
	# 3. configurer les paramètres de Argon2i
	# time_cost=1, memory_cost=8, parallelism=1, hash_len = 8

	type = Type.ID  # Argon2i
	time_cost 	= T # Nombre d'itération (3)
	memory_cost = M # Memoire en Ko ( 64 Mo)
	parallelism = P # Nombre de threads (4)
	hash_len	= 32 #Taille souhaitée pour le hash brut de sortie

	# 4. Générer le hash brut
	resultat = hash_secret_raw( 
					raw_password, 
					sel,
					time_cost, 
					memory_cost, 
					parallelism, 
					hash_len,
					type)
	# 5. Le resultat est retourné par la function cle_maitresse
	return resultat


"""----------------------------------------------------
	Fonction sous_cle
	Utilisation de la fonction de dérivation HKDF-SHA256 pour produire une clé derivée 
	depuis la clé maitresse avec le parametre info=b"coffre-v1|" + usage
	usage est le @Param2 en entré de la function
	# Parametres en entré de la function @Param 1 = maitresse, @Param2 = usage
	Etant supposé que le Paramètre "maitresse" est celui qui produit par cle_maitresse
	----------------------------------------------------
"""
def sous_cle(maitresse:bytes, usage:bytes) -> bytes:
	
	# 1. cle maitresse fourni en parametre
	# maitresse
	
	#2. Le sel(Salt): le sel n'est pas precisé
	sel = None
	
	# 3. Configuration de la function de derivation avec une taille de 32 octets
	myinfo = b"coffre-v1|"  + usage
	hkdf_der = HKDF(
				algorithm=hashes.SHA256(),
				length=32,
				salt=sel,
				info=myinfo
				)
	
	# 4. Générer le hash brut
	result = hkdf_der.derive(maitresse)
	
	# 5. Le resultat est retourné par la function sous_cle
	return result
	
"""----------------------------------------------------
   function CHIFFREMENT utilisant AESGCM
   Donnees associés sont constituées du nom du fichier et des 44 premiers octets(en-tete)
   ----------------------------------------------------
"""
def chiffrer(mot_de_passe:str, nomFichier:str, donnees:bytes) -> bytes:
	
	# 1. Données en entrees
	"""
	Ce sont le mot de passe utilisé pour le chiffrement, le nom du fichier a chiffrer
	et le contenu du fichier en bytes
	"""
	
	# 2. Generation d'un sel aleatoire unique 16 octets
	sel = os.urandom(16)
	
	# 3. Dérivation de la clé avec le mot de passe
	masterKey = cle_maitresse(mot_de_passe, sel)
	cle_pour_chiffrer = sous_cle(masterKey, b"cryptage-fichier")
	#print(f"\nCle pour chiffrer:{cle_pour_chiffrer.hex()}\n")
	
	#4. Initialisation du chiffrement AES-256 avec la clé derivé
	aesgcm_pour_chiffrer = AESGCM(cle_pour_chiffrer)
	
	# 5. Génération d'un nonce 12octets
	nonce = os.urandom(12)
	
	"""
	 6. Constitution des données associées
		6.1. Identifiant du format (4octets)
		6.2. Convertion des donnes time_cost(T = 4octets), memory_cost(M 4octets) et parallelism(P = 4octets)
			en octets dont l'ensemble doit faire 12 octets
	"""
	identifiant_format  = b"CFR1"			   # 4octets
	time_cost_bytes	 =  T.to_bytes(4,'big')  # 4octets
	memory_cost_bytes   = M.to_bytes(4,'big')   # 4octets
	parallelism_bytes   = P.to_bytes(4,'big')   # 4octets
	nomFichier_bytes	= bytes(nomFichier, "utf-8")
		
	entete_data = identifiant_format + time_cost_bytes + memory_cost_bytes + parallelism_bytes
	entete_data += sel +  nonce # sel=16octet et nonce=12octet ==> entete_data= 44octets
	
	data_associee =  entete_data +	bytes(nomFichier, "utf-8")
	
	
	# 6. Chiffrement de la donnée (AES-GCM authentifié )
	data_chiffree = aesgcm_pour_chiffrer.encrypt(nonce, donnees, data_associee)
	
	# 7. Retourner les resultat chiffrer avec 
	resultat_chiffrement = entete_data + data_chiffree
	return resultat_chiffrement

"""----------------------------------------------------
   function DECHIFFREMENT utilisant AESGCM
   
   ----------------------------------------------------
"""
def dechiffrer(mot_de_passe:str, nomFichier:str, blobFichier:bytes) -> bytes:

	# 1. Données en entrees
	"""
	Pour le dechiffrement, il faut retrouver certaines informations initiales utilisées pour chiffrer la donnée
	telles que le sel, le nonce, et bien d'autres
	Ces informations se retrouvent dans le contenu de la variable "blobFichier" en entrée de la fonction de dechiffrement
	Bien entendu, le mot_de_passe et le nomFichier à fournir doivent etre identique aux parametres transmis au chiffrement
	"""
	
	""" 
	2. Retrouver les informations contenues dans le fichier chiffrer "blobFichier"
		Les informations que nous recherchons sont contenu dans les 44 premiers octets de la donnée chiffrée
		
		Rappel: la recuperation est faite relativement à l'ordre de la constitution
		à savoir 
			entete_data = identifiant_format + time_cost_bytes + memory_cost_bytes + parallelism_bytes
			entete_data += sel +  nonce
	"""
	raw_metadata = blobFichier[:44]
	
	identifiant_format  = raw_metadata[:4]	# 4octets
	time_cost_bytes		= raw_metadata[4:8]  # 4octets
	memory_cost_bytes   = raw_metadata[8:12]  # 4octets
	parallelism_bytes   = raw_metadata[12:16]  # 4octets
	sel_de_chiffrement  = raw_metadata[16:32]  # 4octets
	nonce_de_chiffrement  = raw_metadata[-12:]  # 4octets
	
	#2.1 Reconstruire T, M, P
	T =	int.from_bytes(time_cost_bytes, 'big')
	M =	int.from_bytes(memory_cost_bytes, 'big')
	P =	int.from_bytes(parallelism_bytes, 'big')

	
	# 3. Retrouver la clé dérivé grace aux informations receuilli 
	masterKey = cle_maitresse(mot_de_passe, sel_de_chiffrement)
	cle_pour_dechiffrer = sous_cle(masterKey, b"cryptage-fichier")
	
	#print(f"\ncle pour dechiffrer est:{cle_pour_dechiffrer.hex()}")
	
	# 4. Initialisation d'AES-GCM pour le déchiffremen
	aesgcm_dechiffrement = AESGCM(cle_pour_dechiffrer)
	
	
	# 5. Constitution des données associées, raw_data contient les 44octets 
	data_associee = raw_metadata + bytes(nomFichier, "utf-8")
	
	# 6. Constitution des donnees chiffrees sans les informations meta supplementaires
	data_chiffrer = blobFichier[44:]
	
	# Déchiffrement à l'aide du nonce et des données associées reconstruit
	data_dechiffrer = aesgcm_dechiffrement.decrypt(nonce_de_chiffrement, data_chiffrer, data_associee)
	
	return data_dechiffrer
	
	
	
if __name__ == "__main__":
	
	"""
	myMasterKey = cle_maitresse("MonSecretBienGarder", b"teste-mon-secret")
	print(f"Mot de passe: MonSecretBienGarder\n")
	print(f"La clé maitresse est:{myMasterKey.hex()}")

	encryptionKey = sous_cle(myMasterKey, b"test-generation")
	print(f"\nLa clé pour le chiffrement final :{encryptionKey.hex()}\n")
	"""

	donnee_a_chiffrer = b"Mon travail de TP en cryptographie"
	print(f"\nMessage Original:{donnee_a_chiffrer}\n\n")
	
	data_chiffrer = chiffrer("monPassword", "donnees.txt", donnee_a_chiffrer)
	print(f"\nLe Resulat du chiffrement Test:{data_chiffrer.hex()}")
	
	
	data_dechiffrer = dechiffrer("monPassword", "donnees.txt", data_chiffrer)
	
	print(f"\nLe Resulat du Déchiffrement Test:{data_dechiffrer}")