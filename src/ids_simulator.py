# ============================================================
# IDS Simulator - Système de Détection d'Intrusion
# ============================================================

import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from datetime import datetime

# ============================================================
# Chargement du modèle
# ============================================================

print("=" * 55)
print("   🛡️  IDS - Système de Détection d'Intrusion")
print("=" * 55)

model = joblib.load("results/decision_tree_model.pkl")
print("✅ Modèle chargé avec succès !")

# ============================================================
# Chargement des données de test (simulation du trafic réseau)
# ============================================================

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

# Garder les vrais labels pour comparaison
true_labels = data["label"].apply(lambda x: 0 if x == "normal" else 1)
data.drop("label", axis=1, inplace=True)

# ============================================================
# Prétraitement
# ============================================================

le = LabelEncoder()
for col in ["protocol_type", "service", "flag"]:
    data[col] = le.fit_transform(data[col])

scaler = MinMaxScaler()
data_scaled = scaler.fit_transform(data)

# ============================================================
# Simulation du trafic en temps réel (50 connexions)
# ============================================================

print(f"\n📡 Analyse de 50 connexions réseau...\n")
print(f"{'#':<5} {'Heure':<12} {'Résultat':<12} {'Réel':<12} {'Statut'}")
print("-" * 55)

alertes = 0
correctes = 0

for i in range(50):
    connexion = data_scaled[i].reshape(1, -1)
    prediction = model.predict(connexion)[0]
    reel = true_labels.iloc[i]
    heure = datetime.now().strftime("%H:%M:%S")

    resultat = "🔴 ATTAQUE" if prediction == 1 else "🟢 Normal"
    reel_str = "Attaque" if reel == 1 else "Normal"
    statut = "✅" if prediction == reel else "❌"

    if prediction == 1:
        alertes += 1
    if prediction == reel:
        correctes += 1

    print(f"{i+1:<5} {heure:<12} {resultat:<20} {reel_str:<12} {statut}")

# ============================================================
# Résumé final
# ============================================================

print("\n" + "=" * 55)
print("   📊 RÉSUMÉ DE L'ANALYSE")
print("=" * 55)
print(f"  Connexions analysées : 50")
print(f"  Attaques détectées   : {alertes}")
print(f"  Normales             : {50 - alertes}")
print(f"  Prédictions correctes: {correctes}/50")
print(f"  Précision            : {correctes/50*100:.1f}%")
print("=" * 55)