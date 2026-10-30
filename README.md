# Serveur Horus — synchronisation et comptes des praticiens

Ce serveur garde une copie des données de chaque praticien et les envoie à ses appareils
(iPhone, iPad…). **Chaque praticien a son propre compte et ne voit jamais les patients d'un autre.**
Un compte « administrateur » (le premier créé) invite les autres praticiens, désactive ou supprime des comptes.

> **À lire avant de mettre de vrais patients.** Ce document est un guide technique, pas un avis juridique.
> Héberger des données de santé impose un hébergeur **certifié HDS** avec contrat signé, et des démarches RGPD
> (section 8). Proposer ce serveur à d'autres praticiens change ta situation : tu ne l'utilises plus seulement pour
> toi, tu leur fournis un service (section 8). **Tant que tout cela n'est pas réglé, teste uniquement avec des patients fictifs.**

---

## 1. Ce que contient ce dossier
| Fichier | Rôle |
|---|---|
| `server.js` | le serveur (aucun autre fichier nécessaire) |
| `package.json` | indique à l'hébergeur ce qu'il doit installer (la bibliothèque `pg` pour PostgreSQL) |
| `README.md` | ce guide |

Ces fichiers vont dans **un dépôt GitHub séparé** de celui de l'application (par exemple `horus-serveur`),
**à la racine** (pas dans un sous-dossier).

## 2. Ce qu'il te faut chez l'hébergeur
1. Un hébergeur **certifié HDS** proposant une application **Node.js** (version 20 ou plus) et une base **PostgreSQL gérée avec sauvegardes**.
2. **Une seule instance** de l'application (ne pas en lancer plusieurs en parallèle).
3. L'adresse **https** de ton application Horus (par exemple `https://mon-site.netlify.app`).

## 3. Mise en place chez Clever Cloud (vérifie les libellés dans leur console)
1. **Demande l'offre HDS et le contrat** (avec l'annexe de sous-traitance RGPD) avant de mettre de vrais patients.
2. Dans la console, **crée une application** de type **Node.js**. La console propose de lier un **add-on PostgreSQL** :
   accepte, donne-lui un nom. (Plus tard : menu *Service Dependencies* de l'application → *Link add-ons*.)
   L'adresse de la base est alors injectée automatiquement (`DATABASE_URL` ou `POSTGRESQL_ADDON_URI`).
3. **Variables d'environnement** de l'application :

| Variable | Valeur |
|---|---|
| `JWT_SECRET` | texte secret **aléatoire d'au moins 32 caractères** (ton gestionnaire de mots de passe) |
| `SETUP_CODE` | code secret aléatoire : sert à créer le compte administrateur, **et** à récupérer l'accès administrateur si tu perds ton mot de passe. Garde-le secret et conservé. |
| `ALLOWED_ORIGIN` | adresse exacte de ton appli, **sans `/` final** : `https://mon-site.netlify.app` |
| `MAX_USERS` | (facultatif) nombre maximum de praticiens, 20 par défaut |
| `CC_NODE_VERSION` | (facultatif) version de Node.js, par exemple la dernière LTS |

4. Règle le nombre d'instances sur **1**.
5. **Déploie** : relie ton dépôt GitHub à l'application et choisis la branche (ou utilise l'adresse Git de Clever Cloud pour envoyer les fichiers).
   Au démarrage, le serveur crée seul ses tables.
6. Note l'adresse publique (du type `https://xxxx.cleverapps.io`). Ouvre `https://xxxx.cleverapps.io/health` dans Safari :
   tu dois voir `{"ok":true}`.

## 4. Première installation (administrateur)
1. Dans Horus : **Plus → Mode et réglages → Serveur de synchronisation**.
2. Choisis **« Première installation du serveur (administrateur) »**, saisis l'adresse du serveur, ton e-mail,
   un mot de passe de **12 caractères minimum** et le `SETUP_CODE`, puis valide.
3. Tu es connecté en **Administrateur**. Tes données sont envoyées au serveur.

## 5. Ajouter un praticien
1. Toi (administrateur) : **Mode et réglages → Gérer les praticiens → saisis son e-mail → Créer l'invitation**.
2. Un code du type `XXXX-XXXX-XXXX` s'affiche **une seule fois**, valable 7 jours.
   Appuie sur **« Copier le message à envoyer »** et envoie-le au praticien (le message contient tout le chemin à suivre).
3. Lui : dans Horus, **Mode et réglages → Serveur de synchronisation**, choisit **« Créer mon compte avec un code d'invitation »**,
   saisit l'adresse du serveur, son e-mail, le code, et **choisit son propre mot de passe** (tu ne le connais jamais).
4. Son espace est vide et séparé du tien. S'il avait déjà des patients sur son appareil, ils sont envoyés dans **son** espace.

**Autres actions dans « Gérer les praticiens »** :
- **Mot de passe oublié** : génère un code de réinitialisation à lui transmettre (action « Mot de passe oublié » du formulaire).
- **Désactiver / Réactiver** : le praticien est déconnecté aussitôt, ses données sont conservées. Après réactivation, il se reconnecte.
- **Supprimer…** : efface définitivement son compte **et tous ses patients** du serveur (tu retapes son e-mail pour confirmer).
- Chaque praticien peut **changer son mot de passe** lui-même (Mode et réglages → Changer mon mot de passe).

Tu vois pour chacun : actif ou non, nombre de patients, dernière activité. **Tu ne vois jamais le contenu de ses dossiers.**

## 6. Comment ça se comporte
- **Plusieurs appareils d'un même praticien :** synchronisation automatique (à l'ouverture, après chaque modification, au retour du réseau, toutes les minutes). Le point de couleur sur « Plus » indique l'état.
- **Hors ligne :** l'application continue de fonctionner ; les changements partent au retour du réseau.
- **Deux appareils modifient le même patient :** la version la plus récente est gardée (copie de secours : « Annuler la dernière fusion »).
- **Un appareil partagé entre deux praticiens :** si un autre compte se connecte, Horus prévient et retire d'abord les données du précédent de l'appareil (elles restent sur son compte), pour ne jamais mélanger deux praticiens.
- **Sécurité intégrée :** mots de passe chiffrés (scrypt), connexion bloquée 15 minutes après 5 échecs, accès refusé aux sites autres que ton application,
  jetons valables 30 jours et invalidés dès un changement de mot de passe ou une désactivation, journal des connexions et des actions d'administration.
- **Sauvegarde :** vérifie que l'hébergeur sauvegarde la base ; chacun garde aussi l'export de l'application (Plus → Exporter).
- **Accès technique :** quiconque administre l'hébergement et la base de données (toi) a techniquement accès au contenu stocké. À encadrer par contrat et règles d'accès (section 8).

## 7. Perte du mot de passe administrateur
Dans Horus, choisis **« Récupérer l'accès administrateur (code d'installation) »**, saisis ton e-mail, le `SETUP_CODE` et un nouveau mot de passe.
Si tu supprimes `SETUP_CODE` des variables, cette récupération n'est plus possible : garde-le en lieu sûr.

## 8. Responsabilités : à faire valider avant de mettre de vrais patients
Ce n'est pas un avis juridique ; demande conseil à ton Ordre, à la CNIL ou à un délégué à la protection des données (DPO).
- **Hébergement :** hébergeur **certifié HDS**, contrat signé couvrant ce que tu héberges, annexe RGPD.
- **Ton rôle vis-à-vis des autres praticiens :** chaque praticien reste responsable des données de **ses** patients. En leur fournissant ce serveur,
  tu agis vraisemblablement comme **prestataire (sous-traitant)** : cela suppose un **contrat** avec chacun, des engagements de sécurité,
  une procédure en cas de fuite, la gestion des demandes de leurs patients (accès, suppression), et possiblement d'autres obligations
  liées à la fourniture d'un service numérique de santé. À faire cadrer avant d'ouvrir l'accès à d'autres.
- **Registre RGPD, information des patients, durée de conservation, analyse d'impact (AIPD) :** à traiter, par chaque praticien et par toi.
- **Règles d'accès :** qui peut accéder à l'hébergement et à la base ? Limite-le et trace-le.
- **Appareils :** code de verrouillage, mises à jour, un compte par personne (jamais de mot de passe partagé).

## 9. Dépannage
| Message dans Horus | Cause probable |
|---|---|
| « Serveur injoignable » | adresse mal écrite, serveur éteint, pas de réseau, **ou `ALLOWED_ORIGIN` qui ne correspond pas exactement à l'adresse de ton application** (le navigateur bloque alors la réponse). Si `/health` s'affiche dans Safari mais que Horus dit « injoignable », vérifie `ALLOWED_ORIGIN` (`https://`, pas de `/` final, orthographe exacte). |
| « Code invalide, expiré ou déjà utilisé » | code mal recopié, e-mail différent de celui de l'invitation, délai de 7 jours dépassé, ou code déjà servi : demande-en un nouveau |
| « Code d'installation incorrect » | `SETUP_CODE` mal recopié (ou compte administrateur déjà créé : connecte-toi) |
| « Ce compte est désactivé » | contacte l'administrateur |
| « Reconnexion nécessaire » | l'accès a expiré (30 jours), le mot de passe a changé ou le compte a été désactivé : reconnecte-toi, rien n'est perdu |
| « Trop d'essais » | attends 15 minutes |
| « Nombre maximum de praticiens atteint » | supprime un compte inutilisé ou augmente `MAX_USERS` |

Le serveur écrit ses erreurs dans les journaux de l'hébergeur (jamais le contenu des dossiers).

## 10. Mettre à jour le serveur
Remplace `server.js` dans le dépôt : l'hébergeur redéploie. Les données ne sont pas touchées.
