"""Modo atendimento (`desgrampa --atendimento`): para Defensorias, delegacias, serviços de apoio e
universidades que verificam o celular de várias pessoas no mesmo computador.

Cada atendimento começa com o termo de consentimento, recebe um número (ATD-AAAAMMDD-NNN) que vai no
nome das pastas de evidências e termina com a entrega do pacote (.zip com evidências, relatório para
atendimento e termo) e a remoção dos dados deste computador.
"""

import re
import threading
import time
from html import escape

from . import evidence

CASE_RE = re.compile(r"ATD-\d{8}-\d{3}")


class Cases:
    def __init__(self):
        self.lock = threading.Lock()
        self.cases = {}
        self.current = None

    def open(self, consent, name=None, operator=None):
        if consent is not True:
            raise ValueError("é preciso registrar o consentimento da pessoa atendida")
        with self.lock:
            day = time.strftime("%Y%m%d")
            n = 1 + sum(1 for c in self.cases if c.startswith(f"ATD-{day}-"))
            case_id = f"ATD-{day}-{n:03d}"
            self.cases[case_id] = {"id": case_id, "opened": time.strftime("%Y-%m-%d %H:%M:%S"), "closed": None,
                                   "name": (name or "").strip()[:120] or None,
                                   "operator": (operator or "").strip()[:120] or None,
                                   "delivered": False}
            self.current = case_id
            return self.cases[case_id]

    def get(self, case_id):
        case = self.cases.get(case_id)
        if not case:
            raise KeyError(case_id)
        return case

    def reports(self, case_id):
        return [r for r in evidence.list_reports() if r["name"].startswith(f"{case_id}_")]

    def summary(self):
        return {"enabled": True, "current": self.current,
                "cases": [{**c, "reports": self.reports(c["id"])} for c in reversed(list(self.cases.values()))]}

    def package(self, case_id, authority_html, legal):
        """Bytes do .zip do atendimento; authority_html(nome_do_relatorio) gera o relatório para atendimento."""
        case = self.get(case_id)
        names = [r["name"] for r in self.reports(case_id)]
        extra = {f"{name}/atendimento.html": authority_html(name) for name in names}
        extra["termo_de_consentimento.html"] = consent_html(case, legal)
        case["delivered"] = True
        return evidence.zip_reports(names, extra)

    def close(self, case_id):
        """Apaga as evidências do atendimento deste computador e encerra o caso."""
        case = self.get(case_id)
        removed = evidence.delete_reports([r["name"] for r in self.reports(case_id)])
        case["closed"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if self.current == case_id:
            self.current = None
        return removed


def consent_html(case, legal):
    items = "".join(f"<li>{escape(t)}</li>" for t in legal.get("termo", []))
    return ("<!doctype html><html lang=pt-BR><meta charset=utf-8><title>Termo de consentimento</title>"
            "<style>body{font:15px/1.6 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px}"
            ".sig{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:60px}"
            ".sig div{border-top:1px solid #333;padding-top:4px;font-size:13px}</style><body>"
            f"<h1>Termo de consentimento — atendimento {escape(case['id'])}</h1>"
            f"<p>Data e hora: {escape(case['opened'])}"
            + (f" · Pessoa atendida: {escape(case['name'])}" if case.get("name") else "")
            + (f" · Responsável: {escape(case['operator'])}" if case.get("operator") else "")
            + f"</p><ol>{items}</ol><p>Consentimento registrado na tela do Desgrampa no início do atendimento.</p>"
            "<div class=sig><div>Pessoa atendida</div><div>Responsável pelo atendimento</div></div></body></html>")
