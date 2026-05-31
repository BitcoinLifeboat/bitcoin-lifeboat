# Bitcoin Lifeboat error catalog (fr)
# Generated from the stable ErrorCode catalog shape; edit values, not keys.

errors-E-INPUT-001 =
    .title = Entrée vide
    .description = Aucun descripteur ni fichier n’a été fourni.
    .action = Collez un descripteur ou choisissez un fichier.

errors-E-INPUT-002 =
    .title = Entrée trop volumineuse
    .description = Le fichier dépasse la limite de 10 Mo.
    .action = Réduisez le fichier ou contactez le support s’il devrait être plus petit.

errors-E-INPUT-003 =
    .title = Format de fichier invalide
    .description = Le contenu du fichier ne correspond à aucun format connu d’export de portefeuille.
    .action = Vérifiez que le fichier est un descripteur (.txt, .json) ou un export de portefeuille pris en charge.

errors-E-PARSE-001 =
    .title = Le descripteur ne peut pas être analysé
    .description = Le texte fourni n’est pas un descripteur BIP380 valide.
    .action = Vérifiez que vous avez copié le descripteur complet, y compris tout `wsh(`/`wpkh(` initial. En cas de doute, consultez les instructions d’export par portefeuille.

errors-E-PARSE-002 =
    .title = Somme de contrôle du descripteur manquante
    .description = Les descripteurs BIP380 devraient inclure une somme `#xxxxxxxx`.
    .action = Ajoutez la somme de contrôle (Lifeboat peut la calculer) ou réexportez depuis votre portefeuille.

errors-E-PARSE-003 =
    .title = Somme de contrôle du descripteur invalide
    .description = La somme de contrôle du descripteur ne correspond pas à son contenu. Le descripteur a peut-être été mal retranscrit.
    .action = Réexportez le descripteur depuis votre logiciel de portefeuille.

errors-E-PARSE-004 =
    .title = Le descripteur mélange des réseaux
    .description = Le descripteur contient des clés de plusieurs réseaux Bitcoin (par exemple mainnet et testnet).
    .action = C’est presque toujours une erreur. Réexportez le descripteur et vérifiez qu’il contient uniquement des clés mainnet (ou uniquement testnet, si c’est volontaire).

errors-E-PARSE-005 =
    .title = Le descripteur contient des clés privées
    .description = Le descripteur inclut une clé privée étendue (xprv/yprv/zprv/tprv/uprv/vprv) ou une clé privée brute. Lifeboat refuse de traiter les descripteurs qui contiennent du matériel secret.
    .action = Réexportez le descripteur en mode observation seule (xpub au lieu de xprv).

errors-E-PARSE-006 =
    .title = Fonction de descripteur non prise en charge
    .description = Le descripteur utilise une fonction que Lifeboat ne prend pas encore en charge dans cette version (par exemple raw(), addr()).
    .action = Utilisez un portefeuille qui exporte un descripteur pris en charge (wpkh, wsh, sh(wpkh), multi, sortedmulti).

errors-E-PARSE-007 =
    .title = Le seuil multisig dépasse le nombre de clés
    .description = Le descripteur indique M-sur-N avec M > N, ce qui ne peut jamais être satisfait.
    .action = Vérifiez le descripteur; cela indique probablement une erreur de transcription.

errors-E-SECRET-001 =
    .title = Mnémonique BIP39 détectée
    .description = L’entrée contient une suite de mots correspondant à une liste BIP39 avec une somme valide. Lifeboat n’accepte pas les phrases de récupération.
    .action = Exportez le OUTPUT DESCRIPTOR (pas la seed) depuis votre logiciel de portefeuille et collez-le à la place.

errors-E-SECRET-002 =
    .title = Mnémonique BIP39 possible détectée
    .description = L’entrée contient une suite de mots BIP39; la somme n’a pas validé, mais le motif est suspect.
    .action = Si vous vouliez coller un descripteur et qu’il s’agit d’un faux positif, tapez "I confirm this is not a real seed" pour continuer.

errors-E-SECRET-003 =
    .title = Clé privée (WIF) détectée
    .description = L’entrée correspond au format de clé privée WIF. Lifeboat n’accepte pas les clés privées.
    .action = Utilisez plutôt la clé publique correspondante ou un xpub.

errors-E-SECRET-004 =
    .title = Clé privée étendue détectée
    .description = L’entrée contient un xprv / yprv / zprv / tprv / uprv / vprv. Lifeboat n’accepte pas les clés privées étendues.
    .action = Utilisez plutôt le xpub / ypub / zpub / tpub / upub / vpub correspondant.

errors-E-SECRET-005 =
    .title = Part SLIP-39 détectée
    .description = L’entrée semble être une part de sauvegarde Shamir SLIP-39.
    .action = Lifeboat n’a pas besoin de parts SLIP-39. Utilisez le descripteur de sortie de votre portefeuille.

errors-E-SECRET-006 =
    .title = Secret codex32 détecté
    .description = L’entrée semble être un secret codex32 (BIP-93).
    .action = Lifeboat n’a pas besoin de secrets codex32. Utilisez le descripteur de sortie de votre portefeuille.

errors-E-SECRET-007 =
    .title = Clé privée brute possible détectée
    .description = L’entrée contient une chaîne hexadécimale de 64 caractères dans un contexte suspect (par exemple près du mot "private" ou "key").
    .action = Confirmez que ce n’est pas une clé privée. Si vous vouliez utiliser un identifiant de transaction ou un hash de bloc, il ne doit pas apparaître dans ce champ.

errors-E-FS-001 =
    .title = Fichier introuvable
    .description = Le chemin de fichier fourni n’existe pas ou n’est pas lisible.
    .action = Vérifiez le chemin et les permissions, puis réessayez.

errors-E-FS-002 =
    .title = Impossible d’écrire vers la destination
    .description = Le chemin de destination n’est pas accessible en écriture.
    .action = Choisissez une autre destination ou vérifiez les permissions.

errors-E-FS-003 =
    .title = Le fichier de destination existe déjà
    .description = Un fichier existe déjà à la destination.
    .action = Confirmez le remplacement ou choisissez un autre nom.

errors-E-NETWORK-001 =
    .title = Réseau inaccessible
    .description = L’appel réseau lancé par l’utilisateur a échoué.
    .action = Vérifiez votre connexion internet ou réessayez plus tard.

errors-E-NETWORK-002 =
    .title = Appel réseau inattendu tenté
    .description = Interne : un composant a tenté un appel réseau sans action explicite de l’utilisateur.
    .action = C’est un bug. Veuillez ouvrir une issue dans le dépôt GitHub.

errors-E-DEP-001 =
    .title = Typst non inclus
    .description = La génération PDF nécessite le binaire Typst inclus, introuvable.
    .action = Réinstallez Lifeboat. Si le problème persiste, ouvrez une issue.

errors-E-DEP-002 =
    .title = HWI indisponible
    .description = Les opérations de hardware wallet nécessitent le binaire sidecar HWI (v0.4+), introuvable.
    .action = Réinstallez la version de Lifeboat qui inclut HWI, ou utilisez une PSBT par fichier.

errors-E-LINK-001 =
    .title = Lien externe non autorisé
    .description = Le lien n’est pas dans la liste d’URL externes autorisées du projet.
    .action = Vérifiez le lien manuellement dans votre navigateur si vous lui faites confiance.

errors-E-INTERNAL-001 =
    .title = Erreur inattendue
    .description = Une erreur interne inattendue s’est produite.
    .action = Veuillez ouvrir une issue dans le dépôt GitHub avec les étapes de reproduction.

errors-E-INTERNAL-002 =
    .title = Migration de schéma requise
    .description = Le fichier de réglages utilise un format d’une ancienne version de Lifeboat.
    .action = Lifeboat tentera de le migrer. Si cela échoue, supprimez le fichier de réglages.

