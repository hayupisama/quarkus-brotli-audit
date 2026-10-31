# Changelog

Toutes les évolutions notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [0.1.0] - 2026-10-31

### Ajouté
- Audit statique de l'exposition au décodeur Brotli vulnérable (CVE-2026-111497) pour applications Quarkus.
- Contrôles : décompression serveur (`quarkus.http.enable-decompression`), résolution effective de la
  décompression par REST client (ordre builder > spécifique client > global > fallback
  `quarkus.http.enable-compression`), activations programmatiques, support Brotli en compression,
  sources de configuration externes (Dockerfile, compose, k8s, Helm, scripts), autres clients HTTP.
- Statuts `PASS` / `FAIL` / `INCONCLUSIVE` avec garde-fous (jamais « absent = false », jamais
  `INCONCLUSIVE → PASS`).
- Rapports Markdown et JSON ; codes de sortie pour la CI.
- 16 tests (13 scénarios de référence + priorité de résolution + version non vérifiée).
- Règles de résolution vérifiées sur le code source Quarkus 3.33.x et 3.40.x.

### Remarques
- Projet généré avec Claude Code (Anthropic). Voir `NOTICE`.
- L'outil ne reproduit pas la CVE et ne prouve pas l'inexploitabilité (analyse statique).
