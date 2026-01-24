# Système de Partage de Fichiers P2P

Un client peer-to-peer (P2P) pour partager des fichiers avec un serveur central de découverte.

## Compilation

### Compiler le client

```bash
go build -o client cmd/client/main.go
```

Ou utiliser le Makefile s'il existe :

```bash
make build
```

Le binaire `client` sera créé dans le répertoire courant.

## Exécution

### Lancer le client

```bash
./client
```

Une fois le menu affiché, appuyez sur `7` pour activer le mode debug.

## Utilisation du menu

Après le démarrage, un menu interactif s'affiche :

```
--- MENU ---
1. Peers disponibles
2. Connexion à un peer
3. Explorer fichiers distants
4. Télécharger un fichier
5. État des connexions
6. Mes fichiers
7. Activer le mode debug
0. Quitter
```

### Options principales

1. **Peers disponibles** : Liste tous les utilisateurs du réseau
2. **Connexion à un peer** : Se connecte à un autre utilisateur
3. **Explorer fichiers distants** : Parcourt les fichiers d'un autre
4. **Télécharger un fichier** : Télécharge un fichier par son hash SHA256
5. **État des connexions** : Affiche les connexions actives
6. **Mes fichiers** : Affiche votre arborescence partagée
7. **Mode debug** : Active/désactive l'affichage des paquets UDP
0. **Quitter** : Ferme le client

## Auteurs

- Guillaume Xue (22101031)
- David Yu (22110478)

## Licence

Projet universitaire - Programmation Internet
