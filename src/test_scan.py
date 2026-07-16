import socket

cible = "192.168.11.1"   # votre box internet (passerelle)
print(f"🔍 Scan de {cible} sur 40 ports...")

for port in range(1, 41):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        sock.connect((cible, port))
    except:
        pass
    finally:
        sock.close()

print("✅ Scan terminé !")