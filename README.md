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

Une fois le menu affiché, appuyez sur `6` pour activer le mode debug.

## OU
```bash
  make
```

## Utilisation du menu

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

### Options principales

1. **Peers disponibles** : Liste tous les utilisateurs du réseau
2. **Explorer fichiers distants** : Parcourt les fichiers d'un autre
3. **Télécharger un fichier** : Télécharge un fichier
4. **État des connexions** : Affiche les connexions actives
5. **Mes fichiers** : Affiche votre arborescence partagée
6. **Mode debug** : Active/désactive l'affichage des paquets UDP
0. **Quitter** : Ferme le client

## Auteurs

- Guillaume Xue (22101031)
- David Yu (22110478)

## Licence

Projet universitaire - Programmation Internet
