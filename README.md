# Système de Partage de Fichiers P2P

Un client peer-to-peer (P2P) pour partager des fichiers avec un serveur central de découverte. Ce système permet aux utilisateurs de se découvrir mutuellement via un serveur HTTP central et d'échanger des fichiers directement via UDP.

## 📋 Prérequis

- **Go 1.25.1** ou supérieur
- Accès à la clé privée (`client_key.pem`)
- Accès au serveur de découverte central
- Connectivité UDP (port égal au port serveur)
- (Optionnel) Un dossier `shared/` pour stocker les fichiers à partager

## 🔧 Installation & Compilation

### Compiler le client

**Avec make :**
```bash
make
```

**Avec go :**
```bash
go build -o client cmd/client/main.go
```

Le binaire `client` sera créé dans le répertoire courant.

### Installation des dépendances
```bash
go mod download
```

## ▶️ Exécution

### Lancer le client

```bash
./client
```

Le client affichera :
```
======= Client P2P - Système de fichiers =======

✅ Configuration chargée (Peer: nom-du-peer)
✅ Clé privée chargée
✅ Clé publique enregistrée sur le serveur HTTP
✅ Connecté au serveur UDP (81.194.30.229:8443) [Mode: IPv4]
✅ Dossier partagé chargé (root: abc123...)
```

Ensuite, le menu interactif s'affiche.

## 📖 Utilisation du menu

Après le démarrage, un menu interactif s'affiche :

```
--- MENU ---
1. Peers disponibles
2. Explorer fichiers distants
3. Télécharger un fichier
4. État des connexions
5. Mes fichiers
6. Activer le mode debug
0. Quitter
```

### Détail des options

| Option | Description |
|--------|-------------|
| **1** | Affiche la liste de tous les utilisateurs connectés au réseau |
| **2** | Permet de naviguer dans l'arborescence des fichiers d'un autre utilisateur |
| **3** | Télécharge un fichier depuis un pair distante vers votre local |
| **4** | Affiche l'état des connexions TCP/UDP actives |
| **5** | Affiche votre arborescence de fichiers partagés localement |
| **6** | Active/désactive l'affichage détaillé des paquets UDP (mode debug) |
| **0** | Ferme le client avec arrêt gracieux |

## ⚙️ Configuration

Le client se configure via le fichier `config.json` :

### Structure de configuration

```json
{
  "peer": {
    "name": "heee1",                    // Nom unique du client sur le réseau
    "keyfile": "client_key.pem",        // Chemin vers la clé privée RSA
    "shared_dir": "shared",             // Dossier local contenant les fichiers à partager
    "expiry_timeout_minutes": 5         // Délai avant de renouveler l'enregistrement
  },
  "server": {
    "url": "https://jch.irif.fr:8443/peers/",  // URL HTTP du serveur de découverte
    "ipv4_address": "81.194.30.229:8443",      // Adresse IPv4 du serveur UDP
    "ipv6_address": "[2001:660:3301:9243::51c2:1ee5]:8443"  // Adresse IPv6 du serveur
  },
  "network": {
    "timeout_seconds": 3,               // Délai d'attente pour les requêtes réseau
    "keepalive_seconds": 120,           // Intervalle entre les pings de maintien de connexion
    "max_window_size": 256,             // Taille maximale de la fenêtre de flux
    "initial_window": 10,               // Taille initiale de la fenêtre
    // ... autres paramètres de tuning réseau ...
  },
  "merkle": {
    // Configuration de l'arbre de Merkle pour l'intégrité des fichiers
  }
}
```

### Paramètres clés

- **peer.name** : Doit être unique sur le réseau
- **peer.keyfile** : Générée automatiquement si elle n'existe pas
- **peer.shared_dir** : Créée automatiquement si elle n'existe pas
- **server.url** : Point de découverte des pairs sur le réseau
- **server.ipv4_address / ipv6_address** : Adresse UDP pour les transferts directs

### Modification de la configuration

Pour modifier un paramètre, éditez `config.json` avec votre éditeur préféré, puis relancez le client.

## 🏗️ Architecture

### Structure du projet

```
.
├── cmd/
│   └── client/
│       └── main.go              # Point d'entrée du client
├── internal/
│   ├── config/                  # Gestion de la configuration
│   ├── crypto/                  # Chiffrement et gestion des clés RSA
│   ├── menu/                    # Interface utilisateur interactive
│   ├── merkle/                  # Arbre de Merkle pour l'intégrité des fichiers
│   ├── peer/                    # Information et gestion des pairs
│   ├── protocol/                # Protocole de communication (messages, encodage)
│   ├── transport/               # Transport réseau (UDP, TCP, HTTP)
│   └── utils/                   # Utilitaires divers
├── config.json                  # Configuration du client
├── go.mod                        # Dépendances du projet
└── Makefile                      # Commandes de build

```

### Flux de démarrage

1. **Chargement de la config** → `config.json`
2. **Initialisation crypto** → Génération/Chargement de la clé RSA
3. **Enregistrement HTTP** → Publication de la clé publique au serveur
4. **Connexion UDP** → Établissement du tunnel de communication
5. **Initialisation Merkle** → Construction de l'arbre depuis le dossier partagé
6. **Surveillance active** → Watch des modifications de fichiers
7. **Affichage du menu** → Attente des commandes utilisateur

## ✨ Fonctionnalités

- ✅ **Découverte automatique** de pairs via serveur HTTP central
- ✅ **Arbre de Merkle** pour vérifier l'intégrité des fichiers
- ✅ **Chiffrement RSA** de communication
- ✅ **Surveillance en temps réel** des modifications du dossier partagé
- ✅ **Protocole UDP** avec gestion de la fenêtre de flux
- ✅ **Récupération d'intégrité** automatique avec retries
- ✅ **Menu interactif** pour naviguer facilement
- ✅ **Mode debug** pour diagnostiquer les problèmes réseau
- ✅ **Support IPv4 et IPv6**

## 🔍 Mode Debug

Pour diagnostiquer les problèmes de communication :

1. Lancez le client : `./client`
2. Dans le menu, appuyez sur `6` pour activer le mode debug
3. Observez l'affichage des paquets UDP entrants/sortants
4. La sortie affichera tous les messages de protocole

Exemple de sortie :
```
[UDP] ← PEER_LIST_REPLY from 81.194.30.229:8443 (234 bytes)
[UDP] → DOWNLOAD_REQUEST to peer1 (156 bytes)
```

## 🌐 Requêtes REST

Le client communique avec le serveur de découverte central via requêtes HTTP/HTTPS. Voici les endpoints utilisés :

### 1. **GET** - Lister tous les peers
```
GET {server_url}/peers/
```
**Réponse (200 OK) :** Liste de noms séparés par des newlines
```
peer1
peer2
peer3
```

---

### 2. **GET** - Récupérer les adresses d'un peer
```
GET {server_url}/peers/{peer_name}/addresses
```
**Réponse (200 OK) :** Adresses IPv4 et/ou IPv6 du peer
```
81.194.30.229:8443
[2001:660:3301:9243::51c2:1ee5]:8443
```

---

### 3. **GET** - Récupérer la clé publique d'un peer
```
GET {server_url}/peers/{peer_name}/key
```
**Réponse (200 OK) :** Clé publique ECDSA brute (64 bytes)  
**Réponse (404 Not Found) :** Le peer n'existe pas

**Headers :** `Content-Type: application/octet-stream`

---

### 4. **PUT** - Enregistrer/Publier sa clé publique
```
PUT {server_url}/peers/{peer_name}/key
Body: [64 bytes - clé publique ECDSA binaire]
```
**Réponse (200 OK ou 204 No Content) :** Enregistrement réussi

**Headers :** `Content-Type: application/octet-stream`

**Exécution :** Automatique au démarrage du client

---

### Configuration des endpoints REST

Les URLs sont configurées dans `config.json` :
```json
{
  "server": {
    "url": "https://jch.irif.fr:8443/peers/"
  },
  "network": {
    "http_client_timeout": "3s"
  }
}
```

### Exemple de flux HTTP complet

```bash
# 1. Récupérer la liste des peers
curl -k https://jch.irif.fr:8443/peers/

# 2. Récupérer les adresses d'un peer
curl -k https://jch.irif.fr:8443/peers/alice/addresses

# 3. Récupérer la clé publique d'un peer
curl -k https://jch.irif.fr:8443/peers/alice/key -o alice.key

# 4. S'enregistrer soi-même (clé publique)
curl -k -X PUT https://jch.irif.fr:8443/peers/bob/key \
  --data-binary @bob_public.key
```

---

## 🚀 Quickstart

1. **Compilation :**
   ```bash
   make
   ```

2. **Configuration (optionnel) :**
   Éditez `config.json` pour changer le nom du peer, le dossier partagé, etc.

3. **Ajoutez des fichiers :**
   ```bash
   mkdir -p shared
   cp mon_fichier.txt shared/
   ```

4. **Lancez le client :**
   ```bash
   ./client
   ```

5. **Explorez le réseau :**
   - Option 1 : Voir les pairs disponibles
   - Option 2 : Explorer les fichiers d'un autre pair
   - Option 3 : Télécharger un fichier

## 🐛 Troubleshooting

| Problème | Solution |
|----------|----------|
| Erreur `Impossible de charger la clé` | Vérifiez le chemin `keyfile` dans `config.json` |
| Erreur `Impossible de se connecter au serveur UDP` | Vérifiez les paramètres `server.ipv4_address` ou `ipv6_address` |
| Erreur `Impossible de créer le dossier partagé` | Vérifiez les permissions du répertoire courant |
| Pas de pairs disponibles | Attendez quelques secondes et relancez l'option 1 du menu |
| Téléchargement lent | Augmentez `max_window_size` dans la config réseau |
| Perte de connexion fréquente | Augmentez `timeout_seconds` ou `keepalive_seconds` |

## 📝 Fichiers importants

- **config.json** : Configuration principale du client
- **client_key.pem** : Clé privée RSA (générée automatiquement)
- **shared/** : Dossier contenant les fichiers à partager
- **cmd/client/main.go** : Point d'entrée, gestion des signaux CTRL+C

## 📄 Licence

Projet universitaire - **Programmation Internet** (Université de Paris Diderot)

## 📚 Ressources

- Arbre de Merkle : https://fr.wikipedia.org/wiki/Arbre_de_Merkle
- Protocol UDP : https://fr.wikipedia.org/wiki/User_Datagram_Protocol
- P2P : https://fr.wikipedia.org/wiki/Pair_%C3%A0_pair
