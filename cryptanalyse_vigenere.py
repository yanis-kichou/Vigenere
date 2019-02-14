# Sorbonne Université 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : NOM ET NUMERO D'ETUDIANT
# Etudiant.e 2 : NOM ET NUMERO D'ETUDIANT

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

# Chiffrement César
def chiffre_cesar(txt, key):
    """
    Documentation à écrire
    """
    message_chiffrer="" 
    for c in txt:
        message_chiffrer+=chr(((alphabet.index(c)+key)%len(alphabet))+ord('A'))
    txt=message_chiffrer
    return txt

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    Documentation à écrire
    """
    message_claire=""
    for c in txt:
        message_claire+=chr(((alphabet.index(c)-key)%len(alphabet))+ord('A'))
    txt=message_claire
    return txt

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    message_chiffrer=""
    for i in range(0,len(txt)):
        message_chiffrer+=chr((alphabet.index(txt[i])+key[i%len(key)])%len(alphabet)+ord('A'))
    txt=message_chiffrer
    return txt

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    Documentation à écrire
    """
    message_chiffrer=""
    t=len(key)
    al=len(alphabet)
    for i in range(0,len(txt)):
        message_chiffrer+=chr((alphabet.index(txt[i])-key[i%len(key)])%len(alphabet)+ord('A'))
    txt=message_chiffrer
    return txt

# Analyse de fréquences
def freq(txt):
    hist=[0.0]*len(alphabet)
    for lettre in txt:
        hist[alphabet.index(lettre)]+=1 
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    return freq(txt).index(max(freq(txt)))

# indice de coïncidence
def indice_coincidence(hist):
    n=sum(hist)
    somme=0
    for ni in hist:
        somme+=(ni*(ni-1))/(n*(n-1))
    return somme
# Recherche la longueur de la clé
def longueur_clef(cipher):
    for i in range(1,20):
            somme=0.0
            for l in range (1,i):
                somme+=indice_coincidence(freq(cipher[(l-1):len(cipher):i]))
            if(somme/i > 0.06):
                return i
            
    return 0
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    #vecteur qui enregistre le nombre de decalage par lettre de la clef
    decalages=[0]*key_length

    #pour chaque decalage de la clef
    for i in range(0,key_length):
    	#recupere la frequence de la lettre la plus utiliser et lui soustraire ord('E') pour recupere le nombre de pas de decalage (chiffrement cesar)
    	decalages[i]=(lettre_freq_max(cipher[i:len(cipher):key_length])-alphabet.index('E'))%len(alphabet)
    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    	dechiffrement du message cipher en utilisant toutes les fanctiosn deja predefinie qui on permie de recupere la taille de la clef et d'avoir un tableau de decalage decrivant la clef 
    """
    key=longueur_clef(cipher)
    if(len(key))>0:
        return dechiffre_vigenere(cipher,clef_par_decalages(cipher,key))
    return cipher

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    Documentation à écrire
    """
    return 0.0

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Documentation à écrire
    """
    decalages=[0]*key_length
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    Documentation à écrire
    """
    return 0.0

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    Documentation à écrire
    """
    key=[0]*key_length
    score = 0.0
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
