#!/usr/bin/env python3
"""
brotli_audit.py — Audit préventif de l'exposition au décodeur Brotli vulnérable (CVE-2026-111497)
dans une application Quarkus.

PORTÉE (à lire avant toute conclusion)
--------------------------------------
Cet outil fait de l'analyse STATIQUE de configuration et de code. Il vérifie si les chemins connus
d'activation du décodeur Brotli sont neutralisés dans le périmètre audité. Il NE reproduit PAS la CVE,
NE génère aucun flux déclencheur, et NE PEUT PAS garantir que l'application est inexploitable.

  PASS          = les chemins ANALYSÉS sont neutralisés dans le périmètre effectivement audité.
                  (≠ "application immunisée contre la CVE")
  FAIL          = au moins un chemin d'activation est présent/activé (voir fichier:ligne).
  INCONCLUSIVE  = une information nécessaire manque (config de prod hors dépôt, variable d'env
                  inconnue, activation dynamique non résolvable, client HTTP non audité...).

Règles de résolution vérifiées sur le code source Quarkus 3.33.x ET 3.40.x
(io.quarkus.rest.client.reactive.runtime.RestClientBuilderImpl#build, mêmes lignes) :
  décompression effective d'un REST client =
     1) valeur posée par programme sur le builder  (builder.enableCompression(...))
   > 2) config spécifique client   quarkus.rest-client."<clé>".enable-response-decompression
                                    (alias historique: .enable-compression)
   > 3) config globale REST client quarkus.rest-client.enable-compression
   > 4) fallback serveur            quarkus.http.enable-compression
Le premier niveau explicitement présent l'emporte.
Côté serveur entrant : quarkus.http.enable-decompression (défaut false).

Aucune dépendance externe obligatoire (PyYAML utilisé s'il est présent, sinon parseur YAML minimal).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

# Plage de versions pour laquelle les règles de résolution ont été vérifiées sur le code source.
VERIFIED_MIN = (3, 33)
VERIFIED_MAX = (3, 40)

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
# Ordre de gravité pour l'agrégation (FAIL l'emporte, puis INCONCLUSIVE, puis PASS).
_RANK = {PASS: 0, INCONCLUSIVE: 1, FAIL: 2}


def worst(*statuses: str) -> str:
    out = PASS
    for s in statuses:
        if _RANK[s] > _RANK[out]:
            out = s
    return out


# --------------------------------------------------------------------------------------
# Modèle
# --------------------------------------------------------------------------------------
@dataclass
class Found:
    """Une occurrence d'une valeur de configuration, avec sa provenance."""
    key: str
    value: str                 # valeur brute (texte)
    source_kind: str           # properties | yaml | profile | env | dockerfile | compose | k8s | helm | script | java
    location: str              # chemin:ligne
    note: str = ""

    def as_bool(self) -> Optional[bool]:
        v = self.value.strip().strip('"').strip("'").lower()
        if v in ("true", "1", "yes", "on"):
            return True
        if v in ("false", "0", "no", "off"):
            return False
        return None  # présent mais non booléen (ex. expression ${...}) -> indéterminé


@dataclass
class Finding:
    area: str
    status: str
    summary: str
    evidence: list = field(default_factory=list)   # liste de "chemin:ligne — détail"
    detail: str = ""


@dataclass
class Report:
    app: str = ""
    quarkus_version: str = ""
    quarkus_version_source: str = ""
    brotli4j_version: str = ""
    brotli4j_natives: list = field(default_factory=list)
    rules_verified_for_version: bool = True
    global_status: str = PASS
    findings: list = field(default_factory=list)
    clients: list = field(default_factory=list)
    limits: list = field(default_factory=list)


# --------------------------------------------------------------------------------------
# Utilitaires fichiers
# --------------------------------------------------------------------------------------
TEXT_EXT = (".properties", ".yaml", ".yml", ".java", ".xml", ".sh", ".env", ".conf", "")
SKIP_DIRS = {".git", "target", "build", "node_modules", ".idea", ".gradle", "dist", "out"}


def iter_files(root: str):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            yield os.path.join(base, f)


def read_lines(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


# --------------------------------------------------------------------------------------
# Inventaire des dépendances (pom.xml / build.gradle) — best effort
# --------------------------------------------------------------------------------------
def detect_versions(root: str, report: Report):
    quarkus_ver, quarkus_src = "", ""
    brotli_ver = ""
    natives = []
    for path in iter_files(root):
        name = os.path.basename(path).lower()
        if name == "pom.xml":
            lines = read_lines(path)
            text = "\n".join(lines)
            m = re.search(r"<quarkus\.platform\.version>\s*([0-9][^<]+?)\s*</quarkus\.platform\.version>", text)
            if not m:
                m = re.search(r"<quarkus\.version>\s*([0-9][^<]+?)\s*</quarkus\.version>", text)
            if m and not quarkus_ver:
                quarkus_ver, quarkus_src = m.group(1).strip(), rel(root, path)
            for bm in re.finditer(r"<artifactId>\s*(brotli4j|native-[a-z0-9_-]+)\s*</artifactId>\s*<version>\s*([^<]+)</version>", text):
                art, ver = bm.group(1), bm.group(2).strip()
                if art == "brotli4j" and not brotli_ver:
                    brotli_ver = ver
                elif art.startswith("native-"):
                    natives.append(f"{art}:{ver}")
    report.quarkus_version = quarkus_ver or "inconnue"
    report.quarkus_version_source = quarkus_src
    report.brotli4j_version = brotli_ver or "inconnue (transitive — vérifier mvn dependency:tree)"
    report.brotli4j_natives = sorted(set(natives))


def version_tuple(v: str):
    m = re.match(r"(\d+)\.(\d+)", v or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


# --------------------------------------------------------------------------------------
# Parsing des propriétés et YAML
# --------------------------------------------------------------------------------------
PROP_LINE = re.compile(r"^\s*([%A-Za-z0-9_.\"\-]+?)\s*[=:]\s*(.*?)\s*$")


def parse_properties(path: str, root: str):
    """Rend des Found pour chaque ligne clé=valeur, en conservant le préfixe de profil %prof."""
    out = []
    for i, line in enumerate(read_lines(path), start=1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("!"):
            continue
        m = PROP_LINE.match(line)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()
        if "=" not in line and ":" in line:
            # fichier .properties n'utilise que '=' ; ':' ici est probablement du yaml -> ignorer
            if path.endswith(".properties"):
                continue
        kind = "profile" if key.startswith("%") else "properties"
        out.append(Found(key=key, value=val, source_kind=kind, location=f"{rel(root, path)}:{i}"))
    return out


def flatten_yaml_minimal(lines):
    """Parseur YAML minimal (maps imbriquées + scalaires). Retourne [(dotted_key, value, lineno), ...].
    Gère commentaires et guillemets. Ne gère PAS listes/ancres (signalé par l'appelant)."""
    result = []
    stack = []  # (indent, key)
    for i, raw in enumerate(lines, start=1):
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if content.startswith("- "):
            return None  # liste -> abandon (best effort), signalé INCONCLUSIVE
        if ":" not in content:
            continue
        key, _, val = content.partition(":")
        key = key.strip().strip('"').strip("'")
        val = val.strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if val == "":
            stack.append((indent, key))
        else:
            dotted = ".".join([k for _, k in stack] + [key])
            # retire commentaire de fin de ligne non quoté
            if val and val[0] not in "\"'":
                val = val.split(" #", 1)[0].strip()
            val = val.strip('"').strip("'")
            result.append((dotted, val, i))
    return result


def parse_yaml(path: str, root: str, report: Report):
    out = []
    lines = read_lines(path)
    flat = None
    try:
        import yaml  # type: ignore
        data = yaml.safe_load("\n".join(lines)) or {}

        def walk(prefix, node):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(f"{prefix}.{k}" if prefix else str(k), v)
            else:
                out.append(Found(key=prefix, value=str(node), source_kind="yaml",
                                 location=f"{rel(root, path)}", note="pyyaml"))
        walk("", data)
        return out
    except ImportError:
        flat = flatten_yaml_minimal(lines)
    except Exception:
        report.limits.append(f"YAML non analysable de façon fiable: {rel(root, path)} (INCONCLUSIVE)")
        return out
    if flat is None:
        report.limits.append(f"YAML avec listes/structures non gérées par le parseur minimal: {rel(root, path)} "
                             f"(installer PyYAML pour une analyse complète) — INCONCLUSIVE")
        return out
    for dotted, val, ln in flat:
        kind = "profile" if dotted.startswith("%") else "yaml"
        out.append(Found(key=dotted, value=val, source_kind=kind, location=f"{rel(root, path)}:{ln}"))
    return out


# --------------------------------------------------------------------------------------
# Détection des surcharges par variables d'environnement (Dockerfile, compose, k8s, helm, scripts)
# --------------------------------------------------------------------------------------
ENV_TOKENS = {
    "quarkus.http.enable-decompression": re.compile(r"QUARKUS_HTTP_ENABLE_DECOMPRESSION"),
    "quarkus.http.enable-compression": re.compile(r"QUARKUS_HTTP_ENABLE_COMPRESSION"),
    "quarkus.rest-client.enable-compression": re.compile(r"QUARKUS_REST_CLIENT_ENABLE_COMPRESSION\b"),
    # per-client: QUARKUS_REST_CLIENT__<KEY>__ENABLE_(RESPONSE_)?DECOMPRESSION / _COMPRESSION
    "rest-client.per-client": re.compile(r"QUARKUS_REST_CLIENT__[A-Z0-9_]+__ENABLE_(RESPONSE_)?(DE)?COMPRESSION"),
}
ENV_ASSIGN = re.compile(r"([A-Z][A-Z0-9_]+)\s*[=:]\s*[\"']?([^\"'\s#]+)")


def scan_env_overrides(root: str):
    """Retourne des Found correspondant à des surcharges env détectées dans les fichiers du dépôt."""
    out = []
    for path in iter_files(root):
        name = os.path.basename(path).lower()
        kind = None
        if name.startswith("dockerfile"):
            kind = "dockerfile"
        elif name.startswith("docker-compose") or name in ("compose.yaml", "compose.yml"):
            kind = "compose"
        elif name.endswith((".yaml", ".yml")) and _looks_like_k8s(path):
            kind = "k8s"
        elif "values" in name and name.endswith((".yaml", ".yml")):
            kind = "helm"
        elif name.endswith((".sh", ".env")):
            kind = "script"
        if not kind:
            continue
        for i, line in enumerate(read_lines(path), start=1):
            for m in ENV_ASSIGN.finditer(line):
                var, val = m.group(1), m.group(2)
                for canon, rx in ENV_TOKENS.items():
                    if rx.search(var):
                        out.append(Found(key=canon, value=val, source_kind="env",
                                         location=f"{rel(root, path)}:{i}", note=f"via {kind}:{var}"))
    return out


def _looks_like_k8s(path: str) -> bool:
    head = "\n".join(read_lines(path)[:40])
    return bool(re.search(r"^\s*kind\s*:\s*\w+", head, re.M)) and "apiVersion" in head


# --------------------------------------------------------------------------------------
# Scan du code Java : activations programmatiques & clients non audités
# --------------------------------------------------------------------------------------
JAVA_PATTERNS = {
    "builder.enableCompression(true)": re.compile(r"\.enableCompression\s*\(\s*true\s*\)"),
    "builder.enableCompression(var)": re.compile(r"\.enableCompression\s*\(\s*(?!true\s*\)|false\s*\))[^)]+\)"),
    "setDecompressionSupported(true)": re.compile(r"\.setDecompressionSupported\s*\(\s*true\s*\)"),
    "HttpContentDecompressor": re.compile(r"\bHttpContentDecompressor\b"),
    "BrotliDecoder": re.compile(r"\bBrotliDecoder\b"),
    "brotli4j decoder API": re.compile(r"\bDecoder\.decompress\s*\(|Brotli4jLoader|com\.aayushatharva\.brotli4j"),
}
# Clients HTTP non couverts par la résolution Quarkus REST client -> à auditer séparément.
OTHER_HTTP_CLIENTS = {
    "Vert.x WebClient/HttpClient": re.compile(r"\b(WebClient|HttpClient)\b.*\bvertx\b|io\.vertx\.(ext\.web\.client|core\.http)"),
    "OkHttp": re.compile(r"\bokhttp3\b|\bOkHttpClient\b"),
    "Apache HttpClient": re.compile(r"org\.apache\.h(ttp)?components|\bCloseableHttpClient\b|\bHttpClients\b"),
    "JDK HttpClient": re.compile(r"java\.net\.http\.HttpClient"),
}
REGISTER_RC = re.compile(r"@RegisterRestClient\s*(\(\s*configKey\s*=\s*\"([^\"]+)\"\s*\))?")


def scan_java(root: str):
    prog = []          # Found: activations programmatiques
    other_clients = [] # Found: autres clients HTTP
    rc_interfaces = [] # (configKey_or_None, location)
    for path in iter_files(root):
        if not path.endswith(".java"):
            continue
        is_test = "/test/" in rel(root, path) or "\\test\\" in path
        for i, line in enumerate(read_lines(path), start=1):
            code = line.split("//", 1)[0]
            for label, rx in JAVA_PATTERNS.items():
                if rx.search(code):
                    prog.append(Found(key=label, value="", source_kind="java",
                                      location=f"{rel(root, path)}:{i}",
                                      note="(test)" if is_test else ""))
            for label, rx in OTHER_HTTP_CLIENTS.items():
                if rx.search(code):
                    other_clients.append(Found(key=label, value="", source_kind="java",
                                               location=f"{rel(root, path)}:{i}",
                                               note="(test)" if is_test else ""))
            m = REGISTER_RC.search(code)
            if m:
                rc_interfaces.append((m.group(2), f"{rel(root, path)}:{i}", is_test))
    return prog, other_clients, rc_interfaces


# --------------------------------------------------------------------------------------
# Résolution effective
# --------------------------------------------------------------------------------------
def collect_config(root: str, report: Report):
    founds = []
    for path in iter_files(root):
        if path.endswith(".properties"):
            founds += parse_properties(path, root)
        elif path.endswith((".yaml", ".yml")) and ("application" in os.path.basename(path).lower()):
            founds += parse_yaml(path, root, report)
    founds += scan_env_overrides(root)
    return founds


def _match_key(found_key: str, canonical: str) -> bool:
    """Compare en ignorant un éventuel préfixe de profil %prof. et les guillemets de clé client."""
    k = found_key
    if k.startswith("%"):
        k = k.split(".", 1)[1] if "." in k else k
    k = k.replace('"', "")
    return k == canonical


def values_for(founds, canonical: str):
    return [f for f in founds if _match_key(f.key, canonical)]


def decide_boolean(founds, canonical: str, default_absent: Optional[bool]):
    """Retourne (effective_bool_or_None, status, evidence_list).
    - Si une occurrence vaut true  -> True (dangereux potentiel) ; FAIL si certain, sinon porté par l'appelant.
    - Si occurrences non booléennes (expression) -> None + INCONCLUSIVE.
    - Si uniquement false -> False.
    - Si absent -> default_absent (peut être None => fallback géré par l'appelant)."""
    occ = values_for(founds, canonical)
    evidence = [f"{f.location} — {f.key}={f.value} [{f.source_kind}{(' ' + f.note) if f.note else ''}]" for f in occ]
    if not occ:
        return default_absent, PASS, evidence
    bools = [f.as_bool() for f in occ]
    if any(b is None for b in bools):
        return None, INCONCLUSIVE, evidence
    if any(b is True for b in bools):
        return True, PASS, evidence  # statut final décidé par l'appelant (contexte)
    return False, PASS, evidence


def resolve_client_decompression(founds, client_key, prog_activations):
    """Applique l'ordre: builder > per-client > global > fallback http.enable-compression."""
    steps = []
    # 1) builder programmatique (ne peut être lié à un client précis en statique -> traité globalement ailleurs)
    # 2) per-client
    for prop in (f'quarkus.rest-client.{client_key}.enable-response-decompression',
                 f'quarkus.rest-client.{client_key}.enable-compression'):
        occ = values_for(founds, prop)
        if occ:
            b, st, ev = decide_boolean(founds, prop, None)
            return (b, st, f"spécifique client ({prop})", ev)
    # 3) global
    occ = values_for(founds, 'quarkus.rest-client.enable-compression')
    if occ:
        b, st, ev = decide_boolean(founds, 'quarkus.rest-client.enable-compression', None)
        return (b, st, "global rest-client (enable-compression)", ev)
    # 4) fallback
    occ = values_for(founds, 'quarkus.http.enable-compression')
    if occ:
        b, st, ev = decide_boolean(founds, 'quarkus.http.enable-compression', None)
        return (b, st, "fallback quarkus.http.enable-compression", ev)
    return (False, PASS, "défaut (aucune propriété) — décompression désactivée", [])


# --------------------------------------------------------------------------------------
# Audit principal
# --------------------------------------------------------------------------------------
def audit(root: str, prod_config_available: bool) -> Report:
    report = Report(app=os.path.basename(os.path.abspath(root)))
    detect_versions(root, report)
    vt = version_tuple(report.quarkus_version)
    report.rules_verified_for_version = bool(vt and VERIFIED_MIN <= vt <= VERIFIED_MAX)
    if not report.rules_verified_for_version:
        report.limits.append(
            f"Version Quarkus '{report.quarkus_version}' hors de la plage vérifiée "
            f"{VERIFIED_MIN[0]}.{VERIFIED_MIN[1]}.x–{VERIFIED_MAX[0]}.{VERIFIED_MAX[1]}.x : "
            f"la résolution de config doit être reconfirmée sur le code source de cette version (INCONCLUSIVE).")

    founds = collect_config(root, report)
    prog, other_clients, rc_interfaces = scan_java(root)

    # ---- A. Serveur entrant ----
    srv_b, srv_st, srv_ev = decide_boolean(founds, "quarkus.http.enable-decompression", default_absent=False)
    if srv_b is True:
        report.findings.append(Finding("Serveur entrant", FAIL,
            "quarkus.http.enable-decompression=true : le serveur décode les corps de requête (br inclus).",
            srv_ev))
    elif srv_b is None:
        report.findings.append(Finding("Serveur entrant", INCONCLUSIVE,
            "quarkus.http.enable-decompression a une valeur non résolue statiquement.", srv_ev))
    else:
        report.findings.append(Finding("Serveur entrant", PASS,
            "quarkus.http.enable-decompression désactivé (ou défaut false).", srv_ev or ["(aucune occurrence — défaut false)"]))

    # ---- B. REST clients ----
    non_test_prog_enable = [f for f in prog if f.key.startswith("builder.enableCompression") and "(test)" not in f.note]
    client_keys = sorted({ck for ck, _, is_test in rc_interfaces if ck and not is_test})
    # clients déclarés par config quarkus.rest-client.<key>.*
    for f in founds:
        m = re.match(r'(?:%[^.]+\.)?quarkus\.rest-client\.(?!enable-)"?([A-Za-z0-9_.\-]+?)"?\.(enable-|url)', f.key)
        if m:
            client_keys.append(m.group(1))
    client_keys = sorted(set(client_keys))

    if not client_keys:
        report.clients.append({"client": "(aucun REST client détecté par configKey/config)", "effective": "n/a",
                               "source": "-", "status": PASS})
    for ck in client_keys:
        b, st, src, ev = resolve_client_decompression(founds, ck, prog)
        cstatus = st
        if b is True:
            cstatus = FAIL
        elif b is None:
            cstatus = INCONCLUSIVE
        else:
            cstatus = PASS
        report.clients.append({"client": ck, "effective": {True: "décompression ACTIVE", False: "désactivée",
                                None: "indéterminée"}[b], "source": src, "status": cstatus, "evidence": ev})
        report.findings.append(Finding(f"REST client '{ck}'", cstatus,
            f"Décompression effective: {report.clients[-1]['effective']} (origine: {src}).", ev))

    # fallback global applicable même sans client déclaré (clients programmatiques futurs)
    fb_b, fb_st, fb_ev = decide_boolean(founds, "quarkus.http.enable-compression", default_absent=False)
    if fb_b is True:
        report.findings.append(Finding("Fallback REST client", INCONCLUSIVE if not client_keys else PASS,
            "quarkus.http.enable-compression=true : tout REST client SANS config spécifique en hérite "
            "(décodage br des réponses). Vérifier chaque client et les clients créés par programme.", fb_ev))

    # ---- C. Activations programmatiques ----
    hard = [f for f in prog if f.key in ("builder.enableCompression(true)", "setDecompressionSupported(true)",
                                         "HttpContentDecompressor", "BrotliDecoder") and "(test)" not in f.note]
    dynamic = [f for f in prog if f.key in ("builder.enableCompression(var)",) and "(test)" not in f.note]
    direct_api = [f for f in prog if f.key == "brotli4j decoder API" and "(test)" not in f.note]
    if hard:
        report.findings.append(Finding("Activation programmatique", FAIL,
            "Activation explicite de la décompression / usage direct d'un décodeur dans le code applicatif.",
            [f"{f.location} — {f.key}" for f in hard]))
    if direct_api:
        report.findings.append(Finding("Usage direct brotli4j", FAIL,
            "Appel direct à l'API de décodage brotli4j dans le code applicatif.",
            [f"{f.location} — {f.key}" for f in direct_api]))
    if dynamic:
        report.findings.append(Finding("Activation programmatique", INCONCLUSIVE,
            "enableCompression(<variable>) : valeur non déterminable statiquement.",
            [f"{f.location} — {f.key}" for f in dynamic]))
    if not (hard or dynamic or direct_api):
        report.findings.append(Finding("Activation programmatique", PASS,
            "Aucune activation programmatique de décompression dans le code applicatif (src hors tests).", []))

    # ---- D. Support Brotli (compression) — signalé séparément ----
    comp = values_for(founds, "quarkus.http.compressors")
    if any("br" in f.value.lower() for f in comp):
        report.findings.append(Finding("Support Brotli (compression)", INCONCLUSIVE,
            "'br' présent dans quarkus.http.compressors : active le SUPPORT de compression Brotli. "
            "NB: compression ≠ décodeur vulnérable accessible. À noter, pas bloquant en soi.",
            [f"{f.location} — {f.value}" for f in comp]))

    # ---- E. Autres clients HTTP non audités ----
    non_test_other = [f for f in other_clients if "(test)" not in f.note]
    if non_test_other:
        report.findings.append(Finding("Autres clients HTTP", INCONCLUSIVE,
            "Clients HTTP hors résolution Quarkus REST client détectés : comportement de décompression à auditer "
            "séparément (ils n'héritent pas du fallback C7).",
            [f"{f.location} — {f.key}" for f in non_test_other]))

    # ---- F. Config de prod disponible ? ----
    if not prod_config_available:
        report.findings.append(Finding("Config de production", INCONCLUSIVE,
            "La configuration réellement déployée (env/ConfigMap/args JVM de prod) n'est pas garantie présente "
            "dans le dépôt : une valeur 'false' locale peut être surchargée. Fournir --prod-config-available "
            "après vérification de l'environnement réel.", []))
        report.limits.append("Valeurs effectives de production non confirmées (env/ConfigMap/args JVM hors dépôt).")

    report.limits.append("Les activations dynamiques (valeurs calculées à l'exécution) ne sont pas résolues.")
    report.limits.append("PASS = chemins analysés neutralisés dans le périmètre audité, PAS une preuve d'inexploitabilité de la CVE.")

    report.global_status = worst(*[f.status for f in report.findings]) if report.findings else INCONCLUSIVE
    return report


# --------------------------------------------------------------------------------------
# Rapports
# --------------------------------------------------------------------------------------
def to_markdown(r: Report) -> str:
    L = []
    L.append("# Rapport d'audit Brotli (CVE-2026-111497)")
    L.append("")
    L.append(f"- **Application :** {r.app}")
    L.append(f"- **Version Quarkus :** {r.quarkus_version}" + (f" (source: {r.quarkus_version_source})" if r.quarkus_version_source else ""))
    L.append(f"- **Règles de résolution vérifiées pour cette version :** {'oui' if r.rules_verified_for_version else 'NON (voir limites)'}")
    L.append(f"- **brotli4j :** {r.brotli4j_version}")
    if r.brotli4j_natives:
        L.append(f"- **Artefacts natifs :** {', '.join(r.brotli4j_natives)}")
    L.append(f"- **Statut global : {r.global_status}**")
    L.append("")
    L.append("> PASS = les chemins ANALYSÉS sont neutralisés dans le périmètre audité. "
             "Ce n'est PAS une preuve d'inexploitabilité de la CVE.")
    L.append("")
    L.append("## Détail des contrôles")
    for f in r.findings:
        L.append(f"### [{f.status}] {f.area}")
        L.append(f"{f.summary}")
        for e in f.evidence:
            L.append(f"  - {e}")
        if f.detail:
            L.append(f"  - _{f.detail}_")
        L.append("")
    L.append("## REST clients")
    if r.clients:
        L.append("| Client | Décompression effective | Origine | Statut |")
        L.append("|---|---|---|---|")
        for c in r.clients:
            L.append(f"| {c['client']} | {c['effective']} | {c.get('source','-')} | {c['status']} |")
    L.append("")
    L.append("## Éléments non vérifiables / limites")
    for lim in r.limits:
        L.append(f"- {lim}")
    L.append("")
    L.append("## Conclusion")
    L.append(f"Statut global **{r.global_status}**. "
             + {"PASS": "Les chemins d'accès au décodeur analysés sont neutralisés dans le périmètre audité.",
                "FAIL": "Au moins un chemin d'activation du décodeur est présent — voir les findings FAIL.",
                "INCONCLUSIVE": "Des informations manquent pour conclure — voir les findings INCONCLUSIVE et les limites."}[r.global_status])
    return "\n".join(L) + "\n"


def to_json(r: Report) -> str:
    d = asdict(r)
    return json.dumps(d, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
EXIT = {PASS: 0, FAIL: 2, INCONCLUSIVE: 3}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit statique de l'exposition au décodeur Brotli (CVE-2026-111497) d'une app Quarkus.")
    ap.add_argument("project", nargs="?", default=".", help="Racine du projet Quarkus à auditer (défaut: .)")
    ap.add_argument("--out-dir", default=None, help="Répertoire de sortie (défaut: <project>/target)")
    ap.add_argument("--prod-config-available", action="store_true",
                    help="Déclare que la config de production (env/ConfigMap/args JVM) a été vérifiée et est reflétée dans le dépôt.")
    ap.add_argument("--json-only", action="store_true", help="N'écrit que le JSON (pas de Markdown).")
    ap.add_argument("--quiet", action="store_true", help="Pas de résumé stdout.")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.project)
    out_dir = os.path.abspath(args.out_dir) if args.out_dir else os.path.join(root, "target")
    os.makedirs(out_dir, exist_ok=True)

    report = audit(root, prod_config_available=args.prod_config_available)

    json_path = os.path.join(out_dir, "brotli-security-audit.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(to_json(report))
    md_path = None
    if not args.json_only:
        md_path = os.path.join(out_dir, "brotli-security-audit.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(report))

    if not args.quiet:
        print(f"[brotli-audit] statut global: {report.global_status}")
        for f in report.findings:
            if f.status != PASS:
                print(f"  - [{f.status}] {f.area}: {f.summary}")
        print(f"[brotli-audit] rapport JSON: {json_path}")
        if md_path:
            print(f"[brotli-audit] rapport Markdown: {md_path}")
    return EXIT[report.global_status]


if __name__ == "__main__":
    sys.exit(main())
