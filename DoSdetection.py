import math
import random

def DoSdetected(trafficTable):
    packets = len(trafficTable) # liczba wszytskich pakietow
    if packets < 100:
        return

    # Liczenie wystąpień poszczególnych adresów IP
    ipCounts = {}
    for i in trafficTable:
        if i in ipCounts:
            ipCounts[i]+=1
        else:
            ipCounts[i]=1

    
    # Obliczanie entropii na podstawie rozkładu adresów IP
    entropy = 0
    for i in ipCounts:
        p = ipCounts[i]/packets
        if p != 0:
            entropy -= p*math.log2(p)
    
    # Wykrywanie ataku DoS na podstawie entropii
    # Wypisanie węzła, do którego szło najwięcej pakietów
    if entropy < 4.5:
        maks = 0
        dos_Ip=0
        for i in ipCounts:
            maks = max(maks, ipCounts[i])
            if maks==ipCounts[i]:
                dos_Ip=i
        print("Detected DoS attack \nDoS'ed  IP address: " , dos_Ip)
        return True

    return False

# Generowanie losowego ruchu sieciowego
table = []
for i in range (500):
        table.append(random.randint(0,1000))
# Pętla symulująca generowanie ruchu sieciowego (losowe wartości o rozkładzie równomiernym)

# Pętla symuluje atak DoS, wypełniając rejestr ostatnich pakietów jednym docelowym adresem IP
# co oznacza atak DoS wycelowany w ten adres

i = 500
while(i>0):
    i -= 1
    
    table.pop(0)
    table.append(0)

    # Wywołanie funkcji do obliczenia entropii i wykrycia ataku DoS
    if DoSdetected(table): 
        print("Atak wykryty po wysłaniu", 500 - i, "pakietów do węzła 0")
        break
    # Wypisana w warunku if wartość mówi, ile adresów IP hosta, w którego wycelowano atak, 
    # zostało zapisanych w rejestrze do wykrycia ataku
