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

    @unittest.skipUnless(shutil.which("node"), "node não instalado")
    def test_history_compares_scans_of_the_same_device(self):
        script = """
import assert from "node:assert/strict";
import { countsTrend, diffFindings, findingCode, fmtDuration, previousOf, prettyDevice } from "./history.js";
const f = (title, severity = "alta", pkg = null) => ({ title, severity, category: "spyware", package: pkg });
const d = diffFindings([f("A"), f("B"), f("Info", "info")], [f("B"), f("C", "critica", "x.y"), f("Outro info", "info")]);
assert.deepEqual(d.added, [1]);
assert.deepEqual(d.resolved.map((x) => x.title), ["A"]);
assert.equal(d.kept, 1);
assert.deepEqual(countsTrend({ critica: 2, alta: 1 }, { critica: 0, alta: 3 }).map((t) => t.text), ["+2 críticos", "−2 altos"]);
const reports = [
  { name: "b", serial: "S1", started: "2026-10-02 10:00:00" },
  { name: "x", serial: "S2", started: "2026-10-03 10:00:00" },
  { name: "c", serial: "S1", started: "2026-10-03 10:00:00" },
  { name: "a", serial: "S1", started: "2026-10-01 10:00:00" },
];
assert.equal(previousOf("c", "S1", reports).name, "b");
assert.equal(previousOf("a", "S1", reports), null);
assert.equal(findingCode(6), "#07");
assert.equal(fmtDuration(125), "2 min 05 s");
assert.equal(prettyDevice("samsung SM-A515F"), "Samsung SM-A515F");
"""
        proc = subprocess.run(["node", "--input-type=module", "-e", script], cwd=JS, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
