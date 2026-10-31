"""Tests de l'outil d'audit Brotli. Stdlib uniquement (unittest).

Chaque test construit un mini-projet Quarkus temporaire et appelle brotli_audit.audit().
Couvre les 13 scénarios de la spécification + la priorité de résolution.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import brotli_audit as ba  # noqa: E402

POM = """<project><modelVersion>4.0.0</modelVersion>
<properties><quarkus.platform.version>{ver}</quarkus.platform.version></properties>
</project>
"""


def make_project(tmp, props_lines=None, extra_files=None, ver="3.40.1.1"):
    root = tempfile.mkdtemp(dir=tmp)
    with open(os.path.join(root, "pom.xml"), "w", encoding="utf-8") as fh:
        fh.write(POM.format(ver=ver))
    res = os.path.join(root, "src", "main", "resources")
    os.makedirs(res, exist_ok=True)
    with open(os.path.join(res, "application.properties"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(props_lines or []) + "\n")
    for relpath, content in (extra_files or {}).items():
        full = os.path.join(root, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
    return root


def area_status(report, area_prefix):
    for f in report.findings:
        if f.area.startswith(area_prefix):
            return f.status
    return None


def statuses(report, area_prefix):
    return [f.status for f in report.findings if f.area.startswith(area_prefix)]


class BrotliAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()

    # 1
    def test_all_properties_absent(self):
        root = make_project(self.tmp, [])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Serveur entrant"), ba.PASS)
        self.assertEqual(r.global_status, ba.PASS)

    # 2
    def test_server_decompression_enabled(self):
        root = make_project(self.tmp, ["quarkus.http.enable-decompression=true"])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Serveur entrant"), ba.FAIL)
        self.assertEqual(r.global_status, ba.FAIL)

    # 3
    def test_server_decompression_disabled(self):
        root = make_project(self.tmp, ["quarkus.http.enable-decompression=false"])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Serveur entrant"), ba.PASS)

    # 4
    def test_restclient_global_enabled(self):
        root = make_project(self.tmp, [
            "quarkus.rest-client.enable-compression=true",
            "quarkus.rest-client.myclient.url=http://x",
        ])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "REST client 'myclient'"), ba.FAIL)

    # 5
    def test_restclient_global_disabled(self):
        root = make_project(self.tmp, [
            "quarkus.rest-client.enable-compression=false",
            "quarkus.rest-client.myclient.url=http://x",
        ])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "REST client 'myclient'"), ba.PASS)

    # 6
    def test_perclient_enabled_over_global_disabled(self):
        root = make_project(self.tmp, [
            "quarkus.rest-client.enable-compression=false",
            "quarkus.rest-client.myclient.url=http://x",
            "quarkus.rest-client.myclient.enable-response-decompression=true",
        ])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "REST client 'myclient'"), ba.FAIL)

    # 7
    def test_perclient_disabled_over_global_enabled(self):
        root = make_project(self.tmp, [
            "quarkus.rest-client.enable-compression=true",
            "quarkus.rest-client.myclient.url=http://x",
            "quarkus.rest-client.myclient.enable-response-decompression=false",
        ])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "REST client 'myclient'"), ba.PASS)

    # 8
    def test_fallback_http_compression(self):
        root = make_project(self.tmp, [
            "quarkus.http.enable-compression=true",
            "quarkus.rest-client.myclient.url=http://x",
        ])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "REST client 'myclient'"), ba.FAIL)

    # 9
    def test_env_override_dockerfile(self):
        root = make_project(self.tmp, ["quarkus.http.enable-decompression=false"],
                            extra_files={"Dockerfile": "FROM x\nENV QUARKUS_HTTP_ENABLE_DECOMPRESSION=true\n"})
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Serveur entrant"), ba.FAIL)

    # 10
    def test_profile_override(self):
        root = make_project(self.tmp, ["%prod.quarkus.http.enable-decompression=true"])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Serveur entrant"), ba.FAIL)

    # 11
    def test_programmatic_activation(self):
        root = make_project(self.tmp, [], extra_files={
            "src/main/java/app/Client.java":
                "package app;\nclass Client {\n void f(){ builder.enableCompression(true); }\n}\n"})
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Activation programmatique"), ba.FAIL)
        self.assertEqual(r.global_status, ba.FAIL)

    # 12
    def test_unaudited_http_client(self):
        root = make_project(self.tmp, [], extra_files={
            "src/main/java/app/Http.java":
                "package app;\nimport okhttp3.OkHttpClient;\nclass Http { OkHttpClient c; }\n"})
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Autres clients HTTP"), ba.INCONCLUSIVE)

    # 13
    def test_prod_config_missing(self):
        root = make_project(self.tmp, ["quarkus.http.enable-decompression=false"])
        r = ba.audit(root, prod_config_available=False)
        self.assertEqual(area_status(r, "Config de production"), ba.INCONCLUSIVE)
        self.assertEqual(r.global_status, ba.INCONCLUSIVE)

    # bonus : version hors plage vérifiée -> limite signalée
    def test_unverified_version(self):
        root = make_project(self.tmp, [], ver="3.20.0")
        r = ba.audit(root, prod_config_available=True)
        self.assertFalse(r.rules_verified_for_version)

    # bonus : 'br' dans compressors -> signalé séparément (INCONCLUSIVE, pas FAIL en soi)
    def test_brotli_compressor_flag(self):
        root = make_project(self.tmp, ["quarkus.http.compressors=gzip,deflate,br"])
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Support Brotli (compression)"), ba.INCONCLUSIVE)

    # activation programmatique en test -> ignorée (ne doit pas faire FAIL)
    def test_programmatic_in_test_scope_ignored(self):
        root = make_project(self.tmp, [], extra_files={
            "src/test/java/app/ClientTest.java":
                "package app;\nclass ClientTest { void f(){ builder.enableCompression(true);} }\n"})
        r = ba.audit(root, prod_config_available=True)
        self.assertEqual(area_status(r, "Activation programmatique"), ba.PASS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
