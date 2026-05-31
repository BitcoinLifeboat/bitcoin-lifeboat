# Bitcoin Lifeboat error catalog (de)
# Generated from the stable ErrorCode catalog shape; edit values, not keys.

errors-E-INPUT-001 =
    .title = Leere Eingabe
    .description = Es wurde kein Deskriptor und keine Datei angegeben.
    .action = Füge einen Deskriptor ein oder wähle eine Datei.

errors-E-INPUT-002 =
    .title = Eingabe zu groß
    .description = Die Datei überschreitet die Grenze von 10 MB.
    .action = Kürze die Datei oder kontaktiere den Support, wenn sie kleiner sein sollte.

errors-E-INPUT-003 =
    .title = Ungültiges Dateiformat
    .description = Der Dateiinhalt passt zu keinem bekannten Wallet-Exportformat.
    .action = Prüfe, ob die Datei ein Deskriptor (.txt, .json) oder ein unterstützter Wallet-Export ist.

errors-E-PARSE-001 =
    .title = Deskriptor kann nicht gelesen werden
    .description = Der eingegebene Text ist kein gültiger BIP380-Deskriptor.
    .action = Prüfe, ob du den vollständigen Deskriptor kopiert hast, einschließlich eines führenden `wsh(`/`wpkh(`. Wenn du unsicher bist, lies die Exportanleitung für deine Wallet.

errors-E-PARSE-002 =
    .title = Deskriptor-Prüfsumme fehlt
    .description = BIP380-Deskriptoren sollten eine Prüfsumme `#xxxxxxxx` enthalten.
    .action = Füge die Prüfsumme hinzu (Lifeboat kann sie berechnen) oder exportiere erneut aus deiner Wallet.

errors-E-PARSE-003 =
    .title = Deskriptor-Prüfsumme ungültig
    .description = Die Prüfsumme des Deskriptors passt nicht zum Inhalt. Der Deskriptor wurde möglicherweise falsch übertragen.
    .action = Exportiere den Deskriptor erneut aus deiner Wallet-Software.

errors-E-PARSE-004 =
    .title = Deskriptor mischt Netzwerke
    .description = Der Deskriptor enthält Schlüssel aus mehreren Bitcoin-Netzwerken (z. B. Mainnet und Testnet).
    .action = Das ist fast immer ein Fehler. Exportiere den Deskriptor erneut und prüfe, dass er nur Mainnet-Schlüssel enthält (oder nur Testnet, falls beabsichtigt).

errors-E-PARSE-005 =
    .title = Deskriptor enthält private Schlüssel
    .description = Der Deskriptor enthält einen erweiterten privaten Schlüssel (xprv/yprv/zprv/tprv/uprv/vprv) oder einen rohen privaten Schlüssel. Lifeboat verarbeitet keine Deskriptoren mit geheimem Material.
    .action = Exportiere den Deskriptor erneut als Watch-only-Form (xpub statt xprv).

errors-E-PARSE-006 =
    .title = Nicht unterstützte Deskriptorfunktion
    .description = Der Deskriptor nutzt eine Funktion, die Lifeboat in dieser Version noch nicht unterstützt (z. B. raw(), addr()).
    .action = Nutze eine Wallet, die einen unterstützten Deskriptor exportiert (wpkh, wsh, sh(wpkh), multi, sortedmulti).

errors-E-PARSE-007 =
    .title = Multisig-Schwelle übersteigt Schlüsselzahl
    .description = Der Deskriptor gibt M-von-N an, wobei M > N ist; das kann nie erfüllt werden.
    .action = Prüfe den Deskriptor; vermutlich ist dies ein Übertragungsfehler.

errors-E-SECRET-001 =
    .title = BIP39-Mnemonic erkannt
    .description = Die Eingabe enthält eine Wortfolge aus einer BIP39-Wortliste mit gültiger Prüfsumme. Lifeboat akzeptiert keine Seed-Phrases.
    .action = Exportiere den OUTPUT DESCRIPTOR (nicht die Seed) aus deiner Wallet-Software und füge ihn stattdessen ein.

errors-E-SECRET-002 =
    .title = Mögliche BIP39-Mnemonic erkannt
    .description = Die Eingabe enthält eine Folge von BIP39-Wörtern; die Prüfsumme war ungültig, aber das Muster ist verdächtig.
    .action = Wenn du einen Deskriptor einfügen wolltest und dies ein Fehlalarm ist, tippe "I confirm this is not a real seed", um fortzufahren.

errors-E-SECRET-003 =
    .title = Privater Schlüssel (WIF) erkannt
    .description = Die Eingabe entspricht dem WIF-Format für private Schlüssel. Lifeboat akzeptiert keine privaten Schlüssel.
    .action = Nutze stattdessen den passenden öffentlichen Schlüssel oder xpub.

errors-E-SECRET-004 =
    .title = Erweiterter privater Schlüssel erkannt
    .description = Die Eingabe enthält einen xprv / yprv / zprv / tprv / uprv / vprv. Lifeboat akzeptiert keine erweiterten privaten Schlüssel.
    .action = Nutze stattdessen den passenden xpub / ypub / zpub / tpub / upub / vpub.

errors-E-SECRET-005 =
    .title = SLIP-39-Share erkannt
    .description = Die Eingabe scheint ein SLIP-39-Shamir-Backup-Share zu sein.
    .action = Lifeboat braucht keine SLIP-39-Shares. Nutze den Output-Deskriptor deiner Wallet.

errors-E-SECRET-006 =
    .title = codex32-Geheimnis erkannt
    .description = Die Eingabe scheint ein codex32-Geheimnis (BIP-93) zu sein.
    .action = Lifeboat braucht keine codex32-Geheimnisse. Nutze den Output-Deskriptor deiner Wallet.

errors-E-SECRET-007 =
    .title = Möglicher roher privater Schlüssel erkannt
    .description = Die Eingabe enthält eine 64-stellige Hex-Zeichenfolge in einem verdächtigen Kontext (z. B. neben dem Wort "private" oder "key").
    .action = Bestätige, dass dies kein privater Schlüssel ist. Wenn du eine Transaktions-ID oder einen Block-Hash meintest, gehört er nicht in dieses Feld.

errors-E-FS-001 =
    .title = Datei nicht gefunden
    .description = Der angegebene Dateipfad existiert nicht oder ist nicht lesbar.
    .action = Prüfe Pfad und Berechtigungen und versuche es erneut.

errors-E-FS-002 =
    .title = Kann nicht ins Ziel schreiben
    .description = Der Zielpfad ist nicht beschreibbar.
    .action = Wähle ein anderes Ziel oder prüfe die Berechtigungen.

errors-E-FS-003 =
    .title = Zieldatei existiert bereits
    .description = Am Ziel existiert bereits eine Datei.
    .action = Bestätige das Überschreiben oder wähle einen anderen Namen.

errors-E-NETWORK-001 =
    .title = Netzwerk nicht erreichbar
    .description = Der vom Benutzer gestartete Netzwerkaufruf ist fehlgeschlagen.
    .action = Prüfe deine Internetverbindung oder versuche es später erneut.

errors-E-NETWORK-002 =
    .title = Unerwarteter Netzwerkaufruf versucht
    .description = Intern: Eine Komponente hat ohne ausdrückliche Benutzeraktion einen Netzwerkaufruf versucht.
    .action = Das ist ein Fehler. Bitte öffne ein Issue im GitHub-Repository.

errors-E-DEP-001 =
    .title = Typst nicht gebündelt
    .description = PDF-Erzeugung braucht die gebündelte Typst-Binärdatei, die nicht gefunden wurde.
    .action = Installiere Lifeboat erneut. Falls das Problem bleibt, öffne ein Issue.

errors-E-DEP-002 =
    .title = HWI nicht verfügbar
    .description = Hardware-Wallet-Aktionen brauchen die HWI-Sidecar-Binärdatei (v0.4+), die nicht gefunden wurde.
    .action = Installiere die Lifeboat-Version mit HWI erneut oder nutze dateibasierte PSBT.

errors-E-LINK-001 =
    .title = Externer Link nicht erlaubt
    .description = Der Link steht nicht in der Projektliste erlaubter externer URLs.
    .action = Prüfe den Link manuell im Browser, wenn du ihm vertraust.

errors-E-INTERNAL-001 =
    .title = Unerwarteter Fehler
    .description = Ein unerwarteter interner Fehler ist aufgetreten.
    .action = Bitte öffne ein Issue im GitHub-Repository mit den Schritten zur Reproduktion.

errors-E-INTERNAL-002 =
    .title = Schema-Migration erforderlich
    .description = Die Einstellungsdatei nutzt ein Format einer älteren Lifeboat-Version.
    .action = Lifeboat wird versuchen zu migrieren. Wenn das fehlschlägt, lösche die Einstellungsdatei.

