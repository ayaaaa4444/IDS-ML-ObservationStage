# ============================================================
# Dashboard IDS - Poste de supervision (SOC hybride)
# ============================================================

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from datetime import datetime

st.set_page_config(page_title="IDS Console", page_icon="🛡️", layout="wide")

# ---- STYLE ----
st.markdown("""
<style>
    h1,h2,h3,h4 { color:#1E3A8A; font-family:'Segoe UI',sans-serif; }
    .stMetric { background:#F8FAFC; border:1px solid #E2E8F0; border-radius:12px;
                padding:14px; box-shadow:0 1px 3px rgba(0,0,0,0.05); }
    .bandeau { background:linear-gradient(90deg,#1E3A8A,#2563EB); padding:20px 28px;
               border-radius:16px; color:white; margin-bottom:20px;
               display:flex; justify-content:space-between; align-items:center; }
    .bandeau h1 { color:white; margin:0; font-size:26px; }
    .bandeau p { color:#DBEAFE; margin:4px 0 0 0; font-size:13px; }
    .statut { text-align:right; }
    .badge { display:inline-block; padding:6px 14px; border-radius:20px;
             font-weight:700; font-size:14px; }
    .stButton>button { background:#2563EB; color:white; border-radius:8px;
                       border:none; padding:8px 24px; font-weight:600; }
    .stButton>button:hover { background:#1D4ED8; }
</style>
""", unsafe_allow_html=True)

# ---- CHARGEMENT ----
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
    familles = {
        "neptune":"DoS","smurf":"DoS","back":"DoS","teardrop":"DoS","pod":"DoS","land":"DoS",
        "apache2":"DoS","processtable":"DoS","mailbomb":"DoS","udpstorm":"DoS",
        "satan":"Probe","ipsweep":"Probe","portsweep":"Probe","nmap":"Probe","mscan":"Probe","saint":"Probe",
        "guess_passwd":"R2L","ftp_write":"R2L","imap":"R2L","phf":"R2L","multihop":"R2L",
        "warezmaster":"R2L","warezclient":"R2L","spy":"R2L","snmpguess":"R2L","snmpgetattack":"R2L",
        "httptunnel":"R2L","sendmail":"R2L","named":"R2L","xlock":"R2L","xsnoop":"R2L","worm":"R2L",
        "buffer_overflow":"U2R","rootkit":"U2R","loadmodule":"U2R","perl":"U2R","sqlattack":"U2R",
        "xterm":"U2R","ps":"U2R","normal":"Normal"
    }
    le = LabelEncoder()
    for col in ["protocol_type", "service", "flag"]:
        data[col] = le.fit_transform(data[col])
    scaler = MinMaxScaler()
    return scaler.fit_transform(data), true_labels, labels_texte, familles

model = charger_modele()
data_scaled, true_labels, labels_texte, familles = charger_donnees()

# ---- BARRE LATÉRALE ----
with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    nb = st.slider("Connexions à analyser", 10, 1000, 200)
    if st.button("▶️ Lancer l'analyse", type="primary"):
        st.session_state.analyse_lancee = True
        st.session_state.nb_analyse = nb
    st.markdown("---")
    st.caption("Modèle : Arbre de décision")
    st.caption("Dataset : NSL-KDD")
    st.caption("Accuracy : 79,7 %")

# ---- ANALYSE ----
if st.session_state.get("analyse_lancee", False):
    nb = st.session_state.nb_analyse

    preds = model.predict(data_scaled[:nb])
    reels = true_labels.iloc[:nb].values
    types = labels_texte.iloc[:nb].values
    alertes = int(preds.sum())
    correctes = int((preds == reels).sum())
    taux_menace = alertes / nb * 100

    # Niveau de menace
    if taux_menace < 20:
        niveau, couleur = "FAIBLE", "#16A34A"
    elif taux_menace < 50:
        niveau, couleur = "MODÉRÉ", "#F59E0B"
    else:
        niveau, couleur = "ÉLEVÉ", "#DC2626"

    # BANDEAU avec statut
    st.markdown(f"""
    <div class="bandeau">
        <div>
            <h1>🛡️ IDS – Console de supervision</h1>
            <p>TERABYTE SOFTWARE · Détection par Machine Learning</p>
        </div>
        <div class="statut">
            <span class="badge" style="background:{couleur};color:white;">
                NIVEAU DE MENACE : {niveau}
            </span>
            <p style="margin-top:8px;">🟢 Système actif · {datetime.now().strftime("%H:%M:%S")}</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # KPI
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📡 Connexions analysées", nb)
    c2.metric("🔴 Alertes générées", alertes)
    c3.metric("📊 Taux de menace", f"{taux_menace:.1f}%")
    c4.metric("🎯 Précision modèle", f"{correctes/nb*100:.1f}%")

    st.markdown("---")

    # RANGÉE : jauge menace + répartition + familles
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("#### Niveau de menace")
        fig, ax = plt.subplots(figsize=(4, 3), subplot_kw={"aspect": "equal"})
        ax.pie([taux_menace, 100 - taux_menace], colors=[couleur, "#E5E7EB"],
               startangle=180, counterclock=False,
               wedgeprops={"width": 0.35, "edgecolor": "white"})
        ax.text(0, -0.1, f"{taux_menace:.0f}%", ha="center", fontsize=24,
                fontweight="bold", color=couleur)
        ax.text(0, -0.4, niveau, ha="center", fontsize=12, color=couleur)
        st.pyplot(fig)

    with col2:
        st.markdown("#### Trafic")
        fig2, ax2 = plt.subplots(figsize=(4, 3))
        ax2.pie([nb - alertes, alertes], labels=["Normal", "Attaque"],
                colors=["#2563EB", "#EF4444"], autopct="%1.1f%%", startangle=90,
                wedgeprops={"edgecolor": "white", "linewidth": 2})
        st.pyplot(fig2)

    with col3:
        st.markdown("#### Familles d'attaques")
        fam = pd.Series([familles.get(t, "Autre") for t in types if t != "normal"]).value_counts()
        fig3, ax3 = plt.subplots(figsize=(4, 3))
        couleurs_fam = {"DoS":"#DC2626","Probe":"#F59E0B","R2L":"#7C3AED","U2R":"#991B1B","Autre":"#6B7280"}
        ax3.bar(fam.index, fam.values, color=[couleurs_fam.get(f, "#6B7280") for f in fam.index])
        ax3.spines["top"].set_visible(False)
        ax3.spines["right"].set_visible(False)
        st.pyplot(fig3)

    st.markdown("---")

    # BARRE ANALYSTE : filtres
    st.markdown("#### 🔍 Journal des événements")
    f1, f2, f3 = st.columns(3)
    filtre_verdict = f1.selectbox("Filtrer par verdict", ["Tous", "Attaques uniquement", "Normal uniquement"])
    filtre_famille = f2.selectbox("Filtrer par famille", ["Toutes", "DoS", "Probe", "R2L", "U2R"])
    recherche = f3.text_input("Rechercher un type d'attaque", "")

    # Construction du journal
    lignes = []
    for i in range(nb):
        verdict = "Attaque" if preds[i] == 1 else "Normal"
        lignes.append({
            "ID": i + 1,
            "Heure": datetime.now().strftime("%H:%M:%S"),
            "Verdict": verdict,
            "Type réel": types[i],
            "Famille": familles.get(types[i], "Autre"),
            "Correct": "✅" if preds[i] == reels[i] else "❌",
        })
    df = pd.DataFrame(lignes)

    # Filtres
    if filtre_verdict == "Attaques uniquement":
        df = df[df["Verdict"] == "Attaque"]
    elif filtre_verdict == "Normal uniquement":
        df = df[df["Verdict"] == "Normal"]
    if filtre_famille != "Toutes":
        df = df[df["Famille"] == filtre_famille]
    if recherche:
        df = df[df["Type réel"].str.contains(recherche, case=False, na=False)]

    st.dataframe(df, use_container_width=True, height=320)

    # Export
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(" Exporter le journal (CSV)", csv, "journal_ids.csv", "text/csv")

else:
    st.markdown("""
    <div class="bandeau">
        <div>
            <h1> IDS – Console de supervision</h1>
            <p>TERABYTE SOFTWARE · Détection par Machine Learning</p>
        </div>
        <div class="statut">
            <span class="badge" style="background:#6B7280;color:white;">EN ATTENTE</span>
            <p style="margin-top:8px;">⚪ Système en veille</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.info("  Réglez les paramètres dans la barre latérale, puis cliquez sur **Lancer l'analyse**.")