"""Linha de comando do Desgrampa.

    desgrampa                      abre o painel em http://127.0.0.1:8765
    desgrampa --port 9000 --no-browser
    desgrampa atualizar-bases      baixa/atualiza as bases de indicadores
    desgrampa --sem-rastros        relatórios numa pasta temporária, apagada ao fechar
    desgrampa --atendimento        modo para pontos de atendimento (termo, vários aparelhos, pacote e limpeza)
"""

import argparse
import logging
import sys
import webbrowser

from . import __version__, adb, bulletins, iocs, oscompat
from .paths import HOME


def update_bases():
    print("Baixando bases de indicadores (AssoEchap + mvt-indicators) e de vulnerabilidades…")
    try:
        summary = iocs.update().summary()
    except Exception as e:
        print(f"Falhou: {e}", file=sys.stderr)
        return 1
    print(f"Pronto: {summary['total']} indicadores de {len(summary['collections'])} conjuntos.")
    if bulletins.download():
        db = bulletins.summary(bulletins.load())
        print(f"Vulnerabilidades do Android: {db['total']} falhas, boletim mais recente {db['latest_spl']}.")
    else:
        print("Base de vulnerabilidades não atualizada (usando a que vem com o programa).")
    return 0


def serve(port, open_browser, ephemeral=False, attendance=False):
    from .server import serve as make_server

    if not adb.adb_path():
        print("Aviso: 'adb' não encontrado. Instale o Android platform-tools "
              "(ex.: sudo pacman -S android-tools / sudo apt install adb).", file=sys.stderr)
    httpd = make_server(port, ephemeral=ephemeral, attendance=attendance)
    url = f"http://127.0.0.1:{port}/"
    print(f"Desgrampa {__version__} rodando em {url}  (Ctrl+C para sair)")
    if attendance:
        print("Modo atendimento: cada pessoa atendida tem termo, número de atendimento e pacote de evidências; "
              "os relatórios ficam numa pasta temporária apagada ao fechar.")
    elif ephemeral:
        print("Modo sem rastros: os relatórios ficam numa pasta temporária, apagada ao fechar. "
              "Baixe o pacote de evidências antes de sair.")
    else:
        print(f"Dados e relatórios em: {HOME}")
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    finally:
        httpd.state.cleanup()
        if oscompat.FROZEN:
            adb.kill_server()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="desgrampa",
                                     description="Procura spyware e sinais de vigilância em Android via USB.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--port", type=int, default=8765, help="porta do painel local (padrão: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="não abrir o navegador")
    parser.add_argument("--sem-rastros", action="store_true",
                        help="guardar os relatórios numa pasta temporária, apagada ao fechar")
    parser.add_argument("--atendimento", action="store_true",
                        help="modo para pontos de atendimento: termo de consentimento, vários aparelhos e limpeza")
    parser.add_argument("comando", nargs="?", choices=["painel", "atualizar-bases"], default="painel")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    if args.comando == "atualizar-bases":
        return update_bases()
    return serve(args.port, not args.no_browser, ephemeral=args.sem_rastros, attendance=args.atendimento)
