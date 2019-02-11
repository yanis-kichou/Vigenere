from cryptanalyse_vigenere import *
print("\n\n----------------------------------------------\n\n")

print("Test 2 : Vigenere Cipher")

print("---------------------")

print("Test chiffre_vigenere")
assert chiffre_vigenere("ALICE",[0]) == "ALICE"
assert chiffre_vigenere("ALICE",[3]) == "DOLFH"
assert chiffre_vigenere("ALICE",[1,2,3]) == "BNLDG"
print("Test chiffre_vigenere : OK")

print("---------------------")

print("Test dechiffre_cesar")
assert dechiffre_vigenere("ALICE",[0]) == "ALICE"
assert dechiffre_vigenere("DOLFH",[3]) == "ALICE"
assert dechiffre_vigenere("BNLDG",[1,2,3]) == "ALICE"
print("Test dechiffre_vigenere : OK")

print("\n\n----------------------------------------------\n\n")
