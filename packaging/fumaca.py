"""Teste de fumaça do executável único: abre o painel, confere a API, a interface, o adb embutido e as
bases que vêm com o programa, e fecha. Roda no CI em cada sistema, numa máquina sem o Desgrampa instalado.

    python packaging/fumaca.py dist/desgrampa-windows.exe
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

PORT = 8791


def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=5) as resp:
        return resp.status, resp.read()


def main(exe):
    with tempfile.TemporaryDirectory() as home:
        env = {**os.environ, "DESGRAMPA_HOME": home}
        env.pop("DESGRAMPA_ADB", None)
        proc = subprocess.Popen([exe, "--port", str(PORT), "--no-browser", "--sem-rastros"], env=env)
        try:
            for _ in range(60):
                try:
                    status = json.loads(get("/api/status")[1])
                    break
                except OSError:
                    time.sleep(1)
            else:
                raise SystemExit("o painel não respondeu")
            problems = []
            if "platform-tools" not in (status.get("adb") or ""):
                problems.append(f"adb embutido não encontrado: {status.get('adb')}")
            if not status["bulletins"]["available"]:
                problems.append("base de vulnerabilidades ausente")
            if not status["privacy"]["ephemeral"]:
                problems.append("modo sem rastros não ligou")
            for path in ("/", "/js/main.js", "/style.css"):
                if get(path)[0] != 200:
                    problems.append(f"{path} não carregou")
            if len(json.loads(get("/api/ajuda")[1])["defensorias"]) != 27:
                problems.append("dados de ajuda incompletos")
            print(json.dumps({k: status[k] for k in ("version", "system", "adb", "error")}, ensure_ascii=False))
            if problems:
                raise SystemExit("; ".join(problems))
            print("ok")
        finally:
            proc.terminate()
            proc.wait(timeout=30)


if __name__ == "__main__":
    main(sys.argv[1])
