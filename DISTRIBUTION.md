# Distribuer ArgosNet sans blocage antivirus

ArgosNet est un outil d'**analyse réseau** (capture de paquets, scan de ports). Ce type
d'outil, quand il est empaqueté en exécutable **non signé**, est souvent signalé à tort
comme « malveillant » par les antivirus — exactement comme le sont parfois Wireshark ou
Nmap. **Ce n'est pas un vrai malware**, mais il faut composer avec les heuristiques des AV.

Ce document explique comment réduire (voire éliminer) ces faux positifs pour distribuer
ArgosNet à d'autres personnes.

---

## 1. Pourquoi ça arrive

| Cause | Effet |
|-------|-------|
| **Bootloader PyInstaller** | Signature connue des AV (utilisée aussi par des malwares) |
| **Auto-extraction (onefile)** | Décompression en dossier temporaire = comportement « suspect » |
| **Compression UPX** | Les *packers* sont associés aux malwares |
| **Exécutable non signé** | Aucune identité vérifiable → score de confiance très bas |
| **Fichier neuf / rare** | Pas de réputation (SmartScreen, cloud AV) |
| **Sniffing / scan réseau** | Classé « hacktool » par certains moteurs |

---

## 2. Solution gratuite retenue : compiler avec Nuitka

**Nuitka** traduit le code Python en **C compilé** : le binaire ne contient pas le
bootloader PyInstaller, ce qui **réduit fortement** les faux positifs.

```powershell
pip install nuitka

python -m nuitka --standalone --assume-yes-for-downloads `
  --enable-plugin=pyside6 `
  --include-package=scapy `
  --include-package=pyqtgraph `
  --include-data-files=argosnet/core/detection/rules.yaml=argosnet/core/detection/rules.yaml `
  --include-data-files=argosnet/core/detection/blocklist.txt=argosnet/core/detection/blocklist.txt `
  --include-data-files=argosnet/core/detection/ja3_blocklist.txt=argosnet/core/detection/ja3_blocklist.txt `
  --include-data-files=argosnet/resources/argosnet.ico=argosnet/resources/argosnet.ico `
  --windows-icon-from-ico=argosnet/resources/argosnet.ico `
  --windows-console-mode=disable `
  --company-name=ArgosNet --product-name=ArgosNet `
  --file-version=0.1.0 --product-version=0.1.0 `
  --output-dir=build_nuitka run.py
```

Un compilateur C est nécessaire : Nuitka utilise **MSVC** s'il est présent, sinon il
télécharge MinGW-w64 automatiquement (grâce à `--assume-yes-for-downloads`).

**Packaging (déjà automatisé — voir le résultat dans `release/`) :**

```powershell
# 1. Renommer le binaire produit
Rename-Item build_nuitka\run.dist\run.exe ArgosNet.exe

# 2. Emballer le dossier autonome dans un ZIP distribuable
Copy-Item -Recurse build_nuitka\run.dist release\ArgosNet
Compress-Archive -Path release\ArgosNet -DestinationPath release\ArgosNet-win64.zip -Force
```

Le destinataire décompresse le ZIP et lance `ArgosNet\ArgosNet.exe`. Vérification à froid :
`ArgosNet.exe --selftest` (doit afficher « self-test : OK »).

> Le mode `--standalone` (dossier) est **préférable** au `--onefile` pour les antivirus :
> pas d'auto-extraction en temp.
>
> ⚠️ La base **OUI** (constructeurs) n'est pas embarquée (cache utilisateur `~/.cache`) :
> sur une autre machine, la colonne « Constructeur » affiche « — » jusqu'à une mise à jour
> réseau de la base. La capture, le scan et la détection fonctionnent normalement.

---

## 3. La vraie solution pour une diffusion large : la signature de code

Aucune technique gratuite ne garantit 100 % des cas. Pour une distribution sérieuse, il
faut **signer** l'exécutable avec un certificat Authenticode :

- **Certificat OV** (~100-300 €/an) : signe l'exe ; la réputation SmartScreen se construit
  progressivement (quelques avertissements au début).
- **Certificat EV** (~300-500 €/an, clé USB physique) : **réputation SmartScreen
  immédiate**, plus aucun avertissement. C'est le standard des éditeurs.

Signature (une fois le certificat obtenu, avec `signtool` du SDK Windows) :

```powershell
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 ArgosNet.exe
```

---

## 4. Empaqueter proprement (Inno Setup)

Un **installeur** est mieux perçu qu'un exe nu et permet de présenter le projet.
[Inno Setup](https://jrsoftware.org/isinfo.php) (gratuit) génère un `setup.exe` à partir
d'un script `.iss`. Le script est fourni : [`installer/argosnet.iss`](installer/argosnet.iss).

Après avoir compilé l'application (§2) et renommé le binaire en `ArgosNet.exe` (de sorte
que `build_nuitka\run.dist\ArgosNet.exe` existe) :

```powershell
# Compiler l'installeur (Inno Setup 6 installé)
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\argosnet.iss
```

Le résultat, `installer\Output\ArgosNet-Setup-0.1.0.exe`, installe l'application dans
`Program Files`, crée les raccourcis (menu Démarrer + bureau optionnel) et un
désinstalleur, avec l'icône de l'application. Il demande les privilèges administrateur
(nécessaires à la capture/scan). Pensez à **signer aussi l'installeur** (§3) pour une
diffusion large.

---

## 5. Signaler les faux positifs

Pour chaque antivirus qui bloque à tort, soumettez le fichier comme **faux positif** :
l'éditeur l'ajoute en liste blanche (par empreinte SHA-256 — **à refaire à chaque rebuild**,
car l'empreinte change).

- **Surfshark Antivirus** utilise le moteur **Avira** → soumettre ici :
  <https://www.avira.com/fr/analysis/submit-fp>
- **Microsoft Defender / SmartScreen** :
  <https://www.microsoft.com/en-us/wdsi/filesubmission>
- **Vue d'ensemble multi-AV** (voir qui flague) : téléverser sur
  <https://www.virustotal.com> puis soumettre aux éditeurs concernés.

---

## 6. Construire la réputation

- Diffusez toujours **le même binaire signé** avec la **même identité** : la réputation
  cloud s'accumule et les blocages diminuent avec le temps et le nombre de téléchargements.
- Hébergez le code source publiquement (transparence = confiance).
- Documentez clairement l'usage légitime (analyse réseau éducative/défensive).

---

## Récapitulatif des priorités

1. **Compiler avec Nuitka** (fait, §2) — gratuit, gros impact.
2. **Soumettre les faux positifs** à Avira + Microsoft (§5) — gratuit, ciblé.
3. **Distribuer via un installeur** (§4) — meilleure perception.
4. **Signer le code** (§3) — la seule garantie réelle, si diffusion large.
