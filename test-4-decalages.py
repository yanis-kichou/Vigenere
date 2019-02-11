from cryptanalyse_vigenere import *

text1 = read("data/text1.cipher")
text2 = read("data/text2.cipher")

print("\n\n----------------------------------------------\n\n")

print("Test 4 : Decalages naïf")

print("---------------------")

print("Test tableau_decalages_naif")
assert tableau_decalages_naif("GHGHGH",2) == [2,3]
assert tableau_decalages_naif(text1,7) == [10, 9, 7, 0, 24, 22, 0]
assert tableau_decalages_naif(text2,10) == [20, 11, 3, 4, 0, 23, 25, 14, 2, 6]
print("Test tableau_decalages_naif : OK")

print("---------------------")

print("Test dechiffre_decalages")
assert dechiffre_decalages("GHGHGH",[2,3]) == "EEEEEE"
assert dechiffre_decalages(text1, [10, 9, 7, 0, 24, 22, 0]) == read("data/text1.plain")
print("Test dechiffre_decalages : OK")

print("\n\n----------------------------------------------\n\n")
