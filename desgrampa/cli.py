"""Linha de comando do Desgrampa.

    desgrampa                      abre o painel em http://127.0.0.1:8765
    desgrampa --port 9000 --no-browser
    desgrampa atualizar-bases      baixa/atualiza as bases de indicadores
"""

import argparse
import logging
import sys
import webbrowser

from . import __version__, adb, iocs
from .paths import HOME


def update_bases():
    print("Baixando bases de indicadores (AssoEchap + mvt-indicators)…")
    try:
        summary = iocs.update().summary()
    except Exception as e:
        print(f"Falhou: {e}", file=sys.stderr)
        return 1
    print(f"Pronto: {summary['total']} indicadores de {len(summary['collections'])} conjuntos.")
    return 0


def serve(port, open_browser):
    from .server import serve as make_server

    if not adb.adb_path():
        print("Aviso: 'adb' não encontrado. Instale o Android platform-tools "
              "(ex.: sudo pacman -S android-tools / sudo apt install adb).", file=sys.stderr)
    httpd = make_server(port)
    url = f"http://127.0.0.1:{port}/"
    print(f"Desgrampa {__version__} rodando em {url}  (Ctrl+C para sair)")
    print(f"Dados e relatórios em: {HOME}")
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="desgrampa",
                                     description="Procura spyware e sinais de vigilância em Android via USB.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--port", type=int, default=8765, help="porta do painel local (padrão: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="não abrir o navegador")
    parser.add_argument("comando", nargs="?", choices=["painel", "atualizar-bases"], default="painel")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    if args.comando == "atualizar-bases":
        return update_bases()
    return serve(args.port, not args.no_browser)
