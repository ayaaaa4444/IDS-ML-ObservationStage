# ============================================================
# Dashboard IDS unifié - Analyse ML + Surveillance temps réel
# ============================================================

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import threading
import time
from collections import defaultdict
from datetime import datetime
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

st.set_page_config(page_title="IDS - Dashboard", page_icon="🛡️", layout="wide")

# ============================================================
# ÉTAT PARTAGÉ pour la capture temps réel (persiste entre refresh)
# ============================================================

if "capture" not in st.session_state:
    st.session_state.capture = {
        "running": False,
        "stats": {"TCP": 0, "UDP": 0, "ICMP": 0, "Autre": 0},
        "total": 0,
        "alertes": [],
        "ports_par_cible": defaultdict(set),
        "alertes_vues": set(),
        "thread": None,
    }

cap = st.session_state.capture

# ============================================================
# Fonction de capture (tourne dans un thread séparé)
# ============================================================

def demarrer_capture(etat):
    from scapy.all import sniff, IP, TCP, UDP, ICMP

    def analyser(pkt):
        if not etat["running"]:
            return True  # stoppe le sniff
        etat["total"] += 1
        if pkt.haslayer(IP):
            ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
            if pkt.haslayer(TCP):
                etat["stats"]["TCP"] += 1
                cle = f"{ip_src} → {ip_dst}"
                etat["ports_par_cible"][cle].add(pkt[TCP].dport)
                if len(etat["ports_par_cible"][cle]) >= 10 and cle not in etat["alertes_vues"]:
                    etat["alertes_vues"].add(cle)
                    etat["alertes"].append({
                        "Heure": datetime.now().strftime("%H:%M:%S"),
                        "Type": "🔴 Scan de ports",
                        "Source → Cible": cle,
                        "Ports": len(etat["ports_par_cible"][cle]),
                    })
            elif pkt.haslayer(UDP):
                etat["stats"]["UDP"] += 1
            elif pkt.haslayer(ICMP):
                etat["stats"]["ICMP"] += 1
            else:
                etat["stats"]["Autre"] += 1

    sniff(iface="Wi-Fi", prn=analyser, store=False,
          stop_filter=lambda p: not etat["running"])

# ============================================================
# EN-TÊTE
# ============================================================

st.title("🛡️ IDS – Système de Détection d'Intrusion")
st.caption("Stage d'observation – TERABYTE SOFTWARE | Machine Learning (NSL-KDD) + Surveillance temps réel")

tab1, tab2 = st.tabs(["📊 Analyse Machine Learning", "📡 Surveillance temps réel"])

# ============================================================
# ONGLET 1 - ANALYSE ML
# ============================================================

with tab1:
    @st.cache_resource
    def charger_modele():
        return joblib.load("results/decision_tree_model.pkl")

    @st.cache_data
    def charger_donnees():
        columns = [
            "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
            "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
            "root_shell","su_attempted","num_root","num_file_creations","num_shells",
            "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
            "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
            "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
            "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
            "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
            "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
            "label","difficulty"
        ]
        data = pd.read_csv("data/raw/KDDTest+.txt", names=columns)
        data.drop("difficulty", axis=1, inplace=True)
        labels_texte = data["label"].copy()
        true_labels = data["label"].apply(lambda x: 0 if x == "normal" else 1)
        data.drop("label", axis=1, inplace=True)
        le = LabelEncoder()
        for col in ["protocol_type", "service", "flag"]:
            data[col] = le.fit_transform(data[col])
        scaler = MinMaxScaler()
        return scaler.fit_transform(data), true_labels, labels_texte

    model = charger_modele()
    data_scaled, true_labels, labels_texte = charger_donnees()

    nb = st.slider("Nombre de connexions à analyser", 10, 500, 100)
    if st.button("▶️ Lancer l'analyse ML", type="primary"):
        preds = model.predict(data_scaled[:nb])
        reels = true_labels.iloc[:nb].values
        alertes = int(preds.sum())
        correctes = int((preds == reels).sum())

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("📡 Analysées", nb)
        c2.metric("🔴 Alertes", alertes)
        c3.metric("🟢 Normales", nb - alertes)
        c4.metric("🎯 Précision", f"{correctes/nb*100:.1f}%")

        g, d = st.columns(2)
        with g:
            st.subheader("Répartition")
            fig, ax = plt.subplots(figsize=(5, 4))
            ax.pie([nb - alertes, alertes], labels=["Normal", "Attaque"],
                   colors=["steelblue", "tomato"], autopct="%1.1f%%", startangle=90)
            st.pyplot(fig)
        with d:
            st.subheader("Types d'attaques")
            ta = labels_texte.iloc[:nb]
            ta = ta[ta != "normal"].value_counts()
            fig2, ax2 = plt.subplots(figsize=(5, 4))
            ta.plot(kind="barh", color="tomato", ax=ax2)
            st.pyplot(fig2)

# ============================================================
# ONGLET 2 - TEMPS RÉEL
# ============================================================

with tab2:
    st.subheader("Capture du trafic réseau en direct")
    st.info("⚠️ Streamlit doit être lancé en administrateur pour que la capture fonctionne.")

    col_start, col_stop = st.columns(2)
    if col_start.button("▶️ Démarrer la capture", type="primary"):
        if not cap["running"]:
            cap["running"] = True
            t = threading.Thread(target=demarrer_capture, args=(cap,), daemon=True)
            t.start()
            cap["thread"] = t

    if col_stop.button("⏹️ Arrêter la capture"):
        cap["running"] = False

    etat_txt = "🟢 En cours" if cap["running"] else "⚪ Arrêtée"
    st.write(f"**État :** {etat_txt}")

    # Compteurs
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("📦 Paquets totaux", cap["total"])
    k2.metric("TCP", cap["stats"]["TCP"])
    k3.metric("UDP", cap["stats"]["UDP"])
    k4.metric("ICMP", cap["stats"]["ICMP"])

    # Alertes
    st.subheader("🚨 Alertes détectées")
    if cap["alertes"]:
        st.dataframe(pd.DataFrame(cap["alertes"]), use_container_width=True)
    else:
        st.write("Aucune alerte pour le moment.")

    # Rafraîchissement auto quand la capture tourne
    if cap["running"]:
        time.sleep(2)
        st.rerun()