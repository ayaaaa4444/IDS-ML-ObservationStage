# ============================================================
# Dashboard IDS - Mini SOC (Security Operations Center)
# ============================================================

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from datetime import datetime

# ============================================================
# Configuration de la page
# ============================================================

st.set_page_config(page_title="IDS - Mini SOC", page_icon="🛡️", layout="wide")

st.title("🛡️ IDS – Système de Détection d'Intrusion")
st.markdown("**Stage d'observation – TERABYTE SOFTWARE** | Détection basée sur Machine Learning (NSL-KDD)")
st.divider()

# ============================================================
# Chargement du modèle et des données
# ============================================================

@st.cache_resource
def charger_modele():
    return joblib.load("results/decision_tree_model.pkl")

@st.cache_data
def charger_donnees():
    columns = [
        "duration", "protocol_type", "service", "flag", "src_bytes",
        "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
        "num_failed_logins", "logged_in", "num_compromised", "root_shell",
        "su_attempted", "num_root", "num_file_creations", "num_shells",
        "num_access_files", "num_outbound_cmds", "is_host_login",
        "is_guest_login", "count", "srv_count", "serror_rate",
        "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
        "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate", "label", "difficulty"
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
    data_scaled = scaler.fit_transform(data)
    return data_scaled, true_labels, labels_texte

model = charger_modele()
data_scaled, true_labels, labels_texte = charger_donnees()

# ============================================================
# Barre latérale - Contrôles
# ============================================================

st.sidebar.header("⚙️ Paramètres d'analyse")
nb_connexions = st.sidebar.slider("Nombre de connexions à analyser", 10, 500, 100)
lancer = st.sidebar.button("▶️ Lancer l'analyse", type="primary")

# ============================================================
# Analyse
# ============================================================

if lancer:
    echantillon = data_scaled[:nb_connexions]
    predictions = model.predict(echantillon)
    reels = true_labels.iloc[:nb_connexions].values

    nb_alertes = int(predictions.sum())
    nb_normales = nb_connexions - nb_alertes
    nb_correctes = int((predictions == reels).sum())

    # --- Indicateurs clés (KPI) ---
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📡 Connexions analysées", nb_connexions)
    col2.metric("🔴 Alertes générées", nb_alertes)
    col3.metric("🟢 Trafic normal", nb_normales)
    col4.metric("🎯 Précision", f"{nb_correctes/nb_connexions*100:.1f}%")

    st.divider()

    # --- Graphiques ---
    gauche, droite = st.columns(2)

    with gauche:
        st.subheader("Répartition du trafic analysé")
        fig1, ax1 = plt.subplots(figsize=(5, 4))
        ax1.pie([nb_normales, nb_alertes],
                labels=["Normal", "Attaque"],
                colors=["steelblue", "tomato"],
                autopct="%1.1f%%", startangle=90)
        st.pyplot(fig1)

    with droite:
        st.subheader("Types d'attaques réels détectés")
        types_attaques = labels_texte.iloc[:nb_connexions]
        types_attaques = types_attaques[types_attaques != "normal"].value_counts()
        fig2, ax2 = plt.subplots(figsize=(5, 4))
        types_attaques.plot(kind="barh", color="tomato", ax=ax2)
        ax2.set_xlabel("Nombre")
        st.pyplot(fig2)

    st.divider()

    # --- Journal des alertes (mini-SOC) ---
    st.subheader("📋 Journal des alertes")
    journal = []
    for i in range(nb_connexions):
        if predictions[i] == 1:
            journal.append({
                "Heure": datetime.now().strftime("%H:%M:%S"),
                "Connexion #": i + 1,
                "Verdict IDS": "🔴 ATTAQUE",
                "Label réel": labels_texte.iloc[i],
                "Correct": "✅" if reels[i] == 1 else "❌ (fausse alarme)"
            })

    journal_df = pd.DataFrame(journal)
    st.dataframe(journal_df, use_container_width=True, height=300)

    # Sauvegarde du journal (journalisation des événements)
    journal_df.to_csv("results/alerts_log.csv", index=False)
    st.success(f"✅ {len(journal)} alertes journalisées dans results/alerts_log.csv")

else:
    st.info("👈 Choisissez le nombre de connexions puis cliquez sur **Lancer l'analyse**")