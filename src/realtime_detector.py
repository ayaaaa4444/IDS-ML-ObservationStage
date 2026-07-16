# ============================================================
# Détecteur temps réel v4 - Détection par IP cible
# ============================================================

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime

INTERFACE = "Wi-Fi"

print("=" * 60)
print("   🛡️  IDS TEMPS RÉEL v4 - Capture du trafic réseau")
print("=" * 60)
print(f"Interface écoutée : {INTERFACE}")
print("Capture en cours... (Ctrl+C pour arrêter)\n")

stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Autre": 0}
ports_par_cible = defaultdict(set)   # ports contactés PAR cible
alertes_deja_vues = set()
paquets_total = 0

def analyser_paquet(pkt):
    global paquets_total
    paquets_total += 1
    heure = datetime.now().strftime("%H:%M:%S")

    if pkt.haslayer(IP):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
    else:
        return

    if pkt.haslayer(TCP):
        stats["TCP"] += 1
        port_dst = pkt[TCP].dport

        # Clé = paire (source, destination)
        cle = f"{ip_src} -> {ip_dst}"
        ports_par_cible[cle].add(port_dst)

        nb_ports = len(ports_par_cible[cle])
        if nb_ports >= 10 and cle not in alertes_deja_vues:
            alertes_deja_vues.add(cle)
            print(f"\n{'🔴'*20}")
            print(f"🔴 [{heure}] ALERTE : SCAN DE PORTS DÉTECTÉ !")
            print(f"🔴 {cle}")
            print(f"🔴 {nb_ports} ports différents contactés !")
            print(f"{'🔴'*20}\n")

    elif pkt.haslayer(UDP):
        stats["UDP"] += 1
    elif pkt.haslayer(ICMP):
        stats["ICMP"] += 1
    else:
        stats["Autre"] += 1

    if paquets_total % 50 == 0:
        print(f"[{heure}] 📡 {paquets_total} paquets | "
              f"TCP: {stats['TCP']} | UDP: {stats['UDP']} | ICMP: {stats['ICMP']}")

try:
    sniff(iface=INTERFACE, prn=analyser_paquet, count=2000, store=False)
except KeyboardInterrupt:
    pass

print("\n" + "=" * 60)
print("   📊 RÉSUMÉ")
print("=" * 60)
print(f"  Paquets capturés : {paquets_total}")
for proto, n in stats.items():
    print(f"  {proto:<6}: {n}")
print(f"  Alertes de scan  : {len(alertes_deja_vues)}")
print("=" * 60)