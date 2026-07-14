# Feuille de route ArgosNet

Audit du code + backlog de fonctionnalités. Les cases cochées sont **faites**.

---

## 🔧 Audit — corrections

### Bugs corrigés ✅
- [x] **Filtre `ip.addr==` par sous-chaîne** → comparaison exacte
      (`ip.addr==192.168.1.1` ne matche plus `192.168.1.10`). *(display_filter.py)*
- [x] **`CleartextCredsDetector` sans dédup** → une alerte par (source, destination, type),
      fin du spam sur les sessions répétées. *(detectors.py)*
- [x] **Fuite mémoire des détecteurs** (clés IP jamais purgées) → purge périodique des
      fenêtres glissantes. *(detectors.py, `_prune_events`)*
- [x] **`throughput_series()` en O(durée) à chaque tick** → fenêtre glissante bornée
      (1 h), mémoire et coût de rendu bornés. *(stats.py)*
- [x] **`load_pcap` gèle la GUI** → lecture + dissection dans un `QThread` avec barre de
      progression. *(capture_view.py, `PcapLoader`)*
- [x] **Filtre d'affichage sans anti-rebond** → debounce 200 ms. *(capture_view.py)*
- [x] **Table d'alertes non bornée** → plafond d'affichage (2000), l'historique complet
      restant en base SQLite. *(alerts_view.py)*
- [x] Docstring obsolète + constante `HOSTSWEEP_WINDOW` dédiée.

### Restant (mineur) — fait ✅
- [x] `list_interfaces()` mis en cache (copie défensive par appel).
- [x] Commits SQLite regroupés (insertion sans commit + `flush()` périodique 3 s + à la fermeture).
- [x] Indicateur de **perte de paquets** (compteur de tampon plein affiché dans le compteur).
- [x] Chargement `.pcap` **par lots** (lecture incrémentale `PcapReader` + progression + peuplement progressif).

---

## ✨ Backlog de fonctionnalités

### ⚡ Quick wins — fait ✅
- [x] **Double-clic sur une alerte → saut au paquet** concerné (retire le filtre si besoin).
- [x] **Recherche dans les paquets** (Ctrl+F, Suivant/Précédent, Échap).
- [x] **Menu clic droit** sur un paquet : filtrer source/destination/adresse/protocole, copier.
- [x] **Notifications bureau + son** sur alerte critique (basculable dans Affichage).
- [x] **Filtres favoris + historique + autocomplétion** (persistés dans `~/.argosnet/filters.json`).
- [x] **Résumé de capture** (menu Statistiques : durée, pps moyen, hiérarchie des protocoles).

### 🎯 Fortes valeurs
- [x] **Suivre le flux TCP** (Follow Stream, réassemblage — clic droit sur un paquet TCP).
- [x] **Onglet Inventaire des appareils** (base SQLite : MAC, IP, constructeur, vu le/dernier,
      **libellé personnalisé** éditable).
- [x] **Onglet Conversations** (paires d'hôtes triées par volume).
- [x] **Décodeurs enrichis** : HTTP (méthode/URL/host), TLS (SNI), DHCP, mDNS.
- [x] **Éditeur de règles IDS** dans l'UI (menu Détection ; règles utilisateur
      `~/.argosnet/rules.yaml`, rechargées à chaud).
- [x] **Export rapport HTML** d'une session (résumé, protocoles, top talkers,
      conversations, alertes, appareils — menu Fichier).
- [x] **Couleurs de protocole personnalisables** (menu Affichage, persistées).
- [ ] **IO Graph** (débit par protocole dans le temps, à la Wireshark).
- [ ] **Export PDF** (en plus du HTML).
- [ ] **TLS JA3** et **GeoIP / ASN** pour les IP externes (carte + liste).

### 🚀 Ambitieux
- [ ] **Détection étendue** : DNS tunneling, *beaconing* C2 (périodicité), rogue DHCP,
      port knocking, empreinte TLS JA3.
- [ ] **Baseline / détection d'anomalies** (apprentissage du trafic normal).
- [ ] **Threat intel** : comparaison des IP à une blocklist (abuse.ch / Feodo…).
- [ ] **Capture en anneau** avec rotation `.pcap` (monitoring 24/7).
- [ ] **Rejeu / injection de paquets** (Scapy send).
- [ ] **Multi-langue** (EN/FR).
- [ ] **Planification de scans réseau**.

---

## 🚀 Distribution
- [x] Build Nuitka (réduit les faux positifs antivirus) — voir [DISTRIBUTION.md](DISTRIBUTION.md).
- [ ] Installeur Inno Setup + signature de code (certificat OV/EV).
- [ ] Release GitHub avec le ZIP téléchargeable.
- [ ] Icône d'application.
