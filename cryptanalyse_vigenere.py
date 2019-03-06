# Sorbonne Université 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : KICHOU Yanis 3703169   
# Etudiant.e 2 : KHELFOUNE Amayas 3603569

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [0.09213414037491088,0.010354463742221126, 0.030178915678726964, 0.03753683726285317,0.17174710607479665, 0.010939030914707838, 0.01061497737343803,0.010717912027723734, 0.07507240372750529, 0.003832727374391129,6.989390105819367e-05, 0.061368115927295096, 0.026498684088462805,0.07030818127173859, 0.049140495636714375, 0.023697844853330825,0.010160031617459242, 0.06609294363882899, 0.07816806814528274,0.07374314880919855, 0.06356151362232132, 0.01645048271269667,1.14371838095226e-05, 0.004071637436190045, 0.0023001447439151006,0.0012263202640210343] 

# Chiffrement César
def chiffre_cesar(txt, key):
    """
    fonction qui prend un texte et une clef comme argument et crypte le texte en utilisant le chiffrement de Cesar a clef key

    revoie: le terxte crypter
    """
    message_chiffrer="" 
    for c in txt:
        message_chiffrer+=chr(((alphabet.index(c)+key)%len(alphabet))+ord('A'))
    txt=message_chiffrer
    return txt

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
   Dechiffrement de Cesar
    Args:
        txt : le texte à dechiffrer
        key : la clé de Chiffrement
    Returns :
        le texte clair de txt
    """
    message_claire=""
    for c in txt:
        message_claire+=chr(((alphabet.index(c)-key)%len(alphabet))+ord('A'))
    txt=message_claire
    return txt

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    chiffrement de Cesar
    argument :
        txt : le texte à dechiffrer
        key : la clé de Chiffrement
    Retourne:
        le texte crypter de txt
    """
    message_chiffrer=""
    for i in range(0,len(txt)):
        message_chiffrer+=chr((alphabet.index(txt[i])+key[i%len(key)])%len(alphabet)+ord('A'))
    txt=message_chiffrer
    return txt

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    dechiffrement de Cesar
    argument:
        txt : le texte à dechiffrer
        key : la clé de Chiffrement
    Returns :
        le texte clair de txt
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
    """
    fonction freq qui prend en argument un texte et renvoie un tableau designant la frequence d'apparition de chaque lettre de l'alphabet dans le texte
    """
    
    hist=[0.0]*len(alphabet)
    for lettre in txt:
        hist[alphabet.index(lettre)]+=1 
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    fonction qui retorune la lettre la plus frequente dans une texte 
    """
    return freq(txt).index(max(freq(txt)))

# indice de coïncidence
def indice_coincidence(hist):
    """
    fonction qui calcule l'indice de coincidence d'un texte qui prend en argument son histograme designant la frequence d'apparition de chaque lettres 
    retourn l'indice de coincidence de ce texte qui est  la somme des Ni*(Ni-1)/(taille(texte)*(n-1))
    """
    n=sum(hist)
    somme=0
    for ni in hist:
        somme+=(ni*(ni-1))/(n*(n-1))
    return somme
# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    fonction qui retorune la longeur de la clef utiliser lors du cryptage
    cette fonction parcours les 20 taille possible et renvoie la clef qui a comme indice de coincidence supperieur a 0.6 qui represente un texte francais 
    """
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
    	dechiffrement du message cipher en utilisant toutes les fanctions deja predefinie qui on permie de recupere la taille de la clef et d'avoir un tableau de decalage decrivant la clef 
    

    """
    key=longueur_clef(cipher)
    if(key>0):
        return dechiffre_vigenere(cipher,clef_par_decalages(cipher,key))
    return cipher
    """
    1) 11 textes etaient bien cryptanalysé
    2)   Explication : Il est possible d'avoir des textes ou la lettre la plus frequente n'est pas le E, de plus, la fonction lettre_freq_max renvoie la
    lettre la plus frequente par colonne et celle ci peut ne pas etre le chiffre de E, car #il peut y avoir des lettres de meme frequence ou
    de frequence assez proche  et aussi la taille des texte chiffrer est assez importante par rapport a la taille de la clef ce qui aide la chryptanalyse 
    """
################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalages
def indice_coincidence_mutuelle(h1,h2,d):
    """
     Indice de coincidence mutuelle
    arguments :
        h1 : le tableau de fréquences du 1e texte
        h2 : le tableau de fréquences du 2e texte
        d : décalage
    Retourne:
        ICM des deux textes  
    """
    n1=sum(h1)
    n2=sum(h2)
    somme=0.0
    for i in range(0,len(alphabet)):
        somme+=(h1[i]*h2[(i+d)%len(alphabet)])/(n1*n2)
    return somme

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
       Tableau de décalages
    arguments  :
            cipher : le texte chiffré
            key_length : la longueur de la clé
    Returns:
        Tableau de décalages probables etant donne la longueur de la cle
    """
    icm=[]
    decalages=[0]*key_length
    h1=freq(cipher[0:len(cipher):key_length])
    for i in range (len(decalages)):
        for j in range(0,len(alphabet)):
            icm.append(indice_coincidence_mutuelle(h1,freq(cipher[i:len(cipher):key_length]),j))
        decalages[i]=icm.index(max(icm))
        icm=[]
    return decalages
   

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
     Cryptanalyse Version 2 par Indice de coincidence mutuelle
    arguments :
        cipher : le texte chiffré par un cryptage de vigenere 
    Retourne:
        le texte clair
    """
    key_length = longueur_clef(cipher)
    if(key_length != 0):
        # On récupére le tableau de décalages 
        decalages = tableau_decalages_ICM(cipher, key_length)
        j=0
        text_chifrre_en_cesar = ""
        # On parcourt le texte et on décale chaque lettre grâce au tableau décalages
        for i in cipher:
            text_chifrre_en_cesar+=dechiffre_cesar(i, decalages[j%len(decalages)])
            j+=1
        text_dechifrre_en_cesar = ""
        # On récupére la fréquence maximum du texte
        freq_max=lettre_freq_max(text_chifrre_en_cesar)
        # On récupére le décalage
        decalage=(freq_FR.index(max(freq_FR))-freq_max)%len(alphabet)
        for i in text_chifrre_en_cesar:
            text_dechifrre_en_cesar+=chiffre_cesar(i, decalage)
        return text_dechifrre_en_cesar
    else:
        return cipher
    """
    1) le nombre de textes qui ont ete bien cryptanalysé est de 42
    2)  La cryptanalyse basee sur l'indice de coincidence mutuell
    e fournit de meilleurs resultats que ceux obtenus avec la premiere
    approche et en particulier sur des plus petits textes car,
    contrairement à la premiere cryptanalyse ou on raisonnait independamment par colonne,
    nous faisons dans cette approche une analyse de frequences sur tout le texte aligne sur
    le decallage de la premiere colonne. Ceci a pour effet d'augmenter la precision de l'analyse des
    frequences qui reste cepandant peu representative pour les textes tres courts.
    Typiquement, nous pouvons tomber dans le cas ou L'algorithme nous renvoie un chiffre autre que celui de E.
    """
################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    Correlation lineaire de Pearson
    arguments :
        L1,L2 : 2 listes les memes taille pour lesquelles on souhaite calculer la correlation de Pearson
    Retourne:
        Correlation de L1 et L2
    """
    def esperance(X):
        return sum(X)/len(X)

    correlation =0.0
    A=0
    B=0
    C=0
    X=esperance(L1)
    Y=esperance(L2)
    for  i in range(len(L1)):
        A+=(L1[i]-X)*(L2[i]-Y)
        B+=(L1[i]-X)**2
        C+=(L2[i]-Y)**2

    correlation=A /(math.sqrt(B*C))
    return correlation

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
     Clé par Correlations
    arguments :
        cipher : le texte chiffré
        key_length : la longueur de la clé fixé
    Retourne:
        La meilleure clé possible par correlation
    """
    
    key=[0]*key_length
    score = 0.0
    
    for i in range(key_length):
        maxCorel=[0]*len(alphabet)
        for j in range(len(alphabet)):
            maxCorel[j]=correlation(freq(dechiffre_cesar(cipher[i:len(cipher):key_length],j)),freq_FR)
        key[i]=maxCorel.index(max(maxCorel))
        score+=(max(maxCorel)/key_length)
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
     Cryptanalyse Version 3 avec correlations
    arguments :
        cipher : le texte chiffré
    Retourne:
        le texte clair decrypté en utilisant la correlations de peason
    """
    resultat=list()
    for i in range(20):
        resultat.append(clef_correlations(cipher, i))
    score=[a for (a,b) in resultat]

    i=score.index(max(score))
    (s,key)=resultat[i] 
    
    return dechiffre_vigenere(cipher, key)
"""
    1)94 textes etaient bien cryptanalysé
    2-3)Nous obtenons avec cette approche de tres bons résultats et pour des textes bien plus courts que pour la cryptanalyse par IC. Ceci est du au fait qu'on ne se base plus sur l'etude des frequences pour trouver le chiffré de E mais sur le calcul de la correlaton entre une colonne et un texte de reference. Il reste cepandant quelques textes non dechiffres. Ces textes sont tres petits ce qui fait que le nombre de lettres par colonne et leurs dispositions ne sont pas suffisants pour deduire une quelconque correlation avec un texte de reference.

"""

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
