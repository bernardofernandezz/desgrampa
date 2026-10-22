import unittest

from desgrampa import iocs
from desgrampa.checks import packages
from desgrampa.paths import BUNDLED_DATA_DIR

from .test_scan import FIXTURES


class BrazilIndicatorTests(unittest.TestCase):
    def test_bundled_file_is_valid_and_marks_families(self):
        entries = iocs._read_echap(BUNDLED_DATA_DIR / iocs.BR_FILE)
        self.assertTrue(all(e.get("fonte") and e.get("packages") for e in entries))
        loaded = iocs.load(FIXTURES / "iocs")
        self.assertIn("MeuSpy", loaded.sold_in_brazil)
        self.assertEqual(loaded.match_package("com.meuspy").family, "MeuSpy")

    def test_finding_mentions_selling_crime(self):
        base = iocs.Iocs()
        base.add_echap([{"name": "EspiaoTeste", "packages": ["com.systemservice"], "websites": ["espiao.com.br"]}])
        ctx = type("Ctx", (), {"iocs": base})()
        note = packages.sold_in_brazil_note(ctx, base.match_package("com.systemservice"))
        self.assertIn("154-A, § 1º", note)
        self.assertIn("espiao.com.br", note)
