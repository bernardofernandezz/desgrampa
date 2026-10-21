"""Checagens estáticas do front-end (módulos ES sem bundler)."""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

JS = Path(__file__).resolve().parent.parent / "desgrampa" / "web" / "js"
IMPORT = re.compile(r"^import \{([^}]*)\} from \"\./([\w-]+)\.js\";", re.M)
EXPORT = re.compile(r"^export (?:async function|function|const|let) ([\w$]+)", re.M)


class WebModuleTests(unittest.TestCase):
    def test_every_import_has_a_matching_export(self):
        exports = {f.stem: set(EXPORT.findall(f.read_text(encoding="utf-8"))) for f in JS.glob("*.js")}
        problems = []
        for f in JS.glob("*.js"):
            for names, module in IMPORT.findall(f.read_text(encoding="utf-8")):
                if module not in exports:
                    problems.append(f"{f.name}: módulo inexistente ./{module}.js")
                    continue
                for name in (n.strip() for n in names.split(",")):
                    if name not in exports[module]:
                        problems.append(f"{f.name}: '{name}' não é exportado por {module}.js")
        self.assertEqual(problems, [])

    def test_index_loads_main_module(self):
        html = (JS.parent / "index.html").read_text(encoding="utf-8")
        self.assertIn('<script type="module" src="js/main.js"></script>', html)

    @unittest.skipUnless(shutil.which("node"), "node não instalado")
    def test_modules_parse(self):
        for f in sorted(JS.glob("*.js")):
            proc = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"{f.name}: {proc.stderr}")


if __name__ == "__main__":
    unittest.main()
