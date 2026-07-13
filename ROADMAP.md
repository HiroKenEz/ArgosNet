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

### Restant (mineur)
- [ ] `list_interfaces()` appelé 3× au démarrage → mutualiser dans un service partagé.
- [ ] Commits SQLite à chaque drain (250 ms) → regrouper les écritures.
- [ ] Indicateur de **perte de paquets** quand le tampon de capture déborde
      (`deque(maxlen=100000)` jette silencieusement les plus anciens).
- [ ] Chargement `.pcap` : insérer par lots avec progression déterminée (%), pas seulement
      une barre indéterminée.

---

## ✨ Backlog de fonctionnalités

### ⚡ Quick wins
- [ ] **Clic sur une alerte → saut au paquet** concerné (numéros déjà alignés).
- [ ] **Recherche dans les paquets** (Ctrl+F).
- [ ] **Menu clic droit** sur un paquet : « appliquer comme filtre », copier, suivre le flux.
- [ ] **Notifications bureau + son** sur alerte critique.
- [ ] **Filtres favoris + historique + autocomplétion**.
- [ ] **Résumé de capture** (durée, pps moyen, hiérarchie des protocoles).

### 🎯 Fortes valeurs
- [ ] **Suivre le flux TCP/HTTP** (Follow Stream, réassemblage).
- [ ] **Onglet Inventaire des appareils** (base SQLite : MAC, IP, constructeur, vu le/dernier,
      libellé personnalisé).
- [ ] **Éditeur de règles IDS** dans l'UI (au lieu d'éditer `rules.yaml`).
- [ ] **Onglet Conversations + IO Graph** (à la Wireshark).
- [ ] **Export rapport HTML/PDF** d'une session (stats + alertes + top talkers).
- [ ] **Règles de coloration personnalisables**.
- [ ] **Décodeurs enrichis** : HTTP (méthode/URL/host), TLS (SNI/JA3), DHCP, mDNS.
- [ ] **GeoIP / ASN** pour les IP externes (carte + liste).

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
