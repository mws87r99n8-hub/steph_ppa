# Cadran — Connexion personnelle Société Générale avec Enable Banking

Statut : passerelle intégrée, **non activée** tant que les identifiants Enable Banking ne sont pas configurés.

## Adresses Cadran

- Application avec serveur bancaire : https://cadran-budget-connect.onrender.com
- Configuration du serveur Render : https://dashboard.render.com/web/srv-dbqe3vtg1s2s73e2hu10
- Confidentialité : https://cadran-budget-connect.onrender.com/privacy.html
- Conditions : https://cadran-budget-connect.onrender.com/terms.html
- Retour d'autorisation à enregistrer dans Enable Banking : https://cadran-budget-connect.onrender.com/api/bank/callback

## Création du compte personnel

1. Se rendre sur https://enablebanking.com/sign-in/ et créer un accès personnel.
2. Enregistrer une application **PRODUCTION** appelée Cadran (le mode Sandbox ne permet pas de connecter un vrai compte).
3. Utiliser la génération de clé/certificat RSA depuis le navigateur dans le Control Panel ou générer une paire RSA localement. Conserver **exclusivement** la clé privée, ne pas l'envoyer dans ChatGPT ni dans GitHub.
4. Dans le formulaire d'enregistrement de l'application renseigner :
   - Redirect URL : https://cadran-budget-connect.onrender.com/api/bank/callback
   - Privacy URL : https://cadran-budget-connect.onrender.com/privacy.html
   - Terms URL : https://cadran-budget-connect.onrender.com/terms.html
   - GDPR Email : une adresse email que vous gérez
   - Description : Application budgétaire personnelle non commerciale en lecture seule
5. Dans le Control Panel, choisir « Activate by linking accounts » pour associer **votre propre compte Société Générale** et activer le mode production restreint, autorisé à un particulier pour ses comptes propres.
6. Dans Render > Environment renseigner personnellement (sans les publier) :
   - `ENABLE_BANKING_APP_ID` : ID de l'application reçu par Enable Banking
   - `ENABLE_BANKING_PRIVATE_KEY` : contenu PEM complet de la clé RSA privée (multiligne, ou avec les séquences littérales \n)
   - `APP_PASSWORD` : mot de passe personnel long et unique pour Cadran, au moins 12 caractères
   - `APP_SESSION_SECRET` : déjà généré et configuré sur Render (ne le remplacer que si nécessaire)
   - `APP_PUBLIC_URL` : déjà configuré, https://cadran-budget-connect.onrender.com
7. Une fois la mise à jour Render terminée, aller dans Cadran > Comptes > Connexion bancaire : déverrouiller le module, connecter Société Générale, consentir dans le parcours Enable Banking / L'Appli SG. Un retour réussi provoque la première synchronisation.

## Sécurité et fonctionnement

- Les secrets RSA et le mot de passe ne sont jamais envoyés au navigateur et ne doivent **jamais** être copiés dans GitHub ou une conversation.
- Une session bancaire est mémorisée dans un cookie chiffré, HttpOnly, Secure, SameSite=Lax, expirant au plus tard avec le consentement demandé.
- Les données bancaires synchronisées sont conservées **en mémoire** dans l'application ; elles ne sont pas stockées durablement en clair dans localStorage. À la prochaine ouverture, déverrouiller Cadran pour les resynchroniser.
- Les dépenses manuelles, budgets et échéances peuvent rester enregistrés en clair dans le navigateur. Ne pas utiliser l'application avec des informations sensibles sur un appareil partagé.
- Le backend ne fait aucun virement et n'appelle aucune API de paiement.
- Si le consentement expire, se reconnecter et le renouveler. Le serveur ne lance pas de tâche de fond non authentifiée.
- Limites : la synchronisation ne fonctionne pas sans consentement et sans accès production ; le mode restreint Enable Banking ne permet de lire que les comptes préalablement liés par leur propriétaire.
- Les comptes non EUR ne sont pas importés dans Cadran. La période de transactions récupérée par synchronisation est limitée aux 89 derniers jours, dans la limite des historiques disponibles chez SG.

Documentation officielle : https://enablebanking.com/docs/api/reference et https://enablebanking.com/docs/api/linked-accounts
