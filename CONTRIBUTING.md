# Contribuindo com o Desgrampa

Obrigado pelo interesse! Este projeto ajuda pessoas em situação de risco, então duas regras valem acima
de todas as outras:

1. **A varredura nunca altera o aparelho.** Verificações só podem usar comandos de leitura. Alterações
   (remover/desativar app) existem apenas em `desgrampa/actions.py`, disparadas por confirmação manual
   na interface.
2. **Privacidade em primeiro lugar.** Nunca anexe relatórios, prints ou saídas de `adb` de um aparelho
   real em issues ou PRs. Use dados fictícios, como os de `tests/fake_device.py`.

## Ambiente

```bash
git clone https://github.com/bernardofernandezz/desgrampa && cd desgrampa
python -m venv .venv
.venv/bin/pip install -e ".[dev,forense]"
.venv/bin/python -m unittest -v
.venv/bin/ruff check desgrampa tests
.venv/bin/desgrampa
```

Os testes rodam **offline**: usam um aparelho falso (`tests/fake_device.py`) e bases de indicadores
mínimas (`tests/fixtures/iocs`). Para testar a interface sem celular, aponte `DESGRAMPA_ADB` para um
script que imite o `adb` (veja `tests/fake_device.py`).

## Estrutura

```
desgrampa/
  cli.py          comando `desgrampa`
  server.py       servidor HTTP local (127.0.0.1) e API usada pela interface
  scanner.py      orquestra as verificações, calcula o veredito e salva as evidências
  context.py      coleta de dados do aparelho (com cache) e parsers das saídas do adb
  checks/         uma verificação por arquivo (veja abaixo)
  iocs.py         bases de indicadores (AssoEchap + STIX2 do MVT)
  grouping.py     agrupamento categoria → origem e sugestões de remoção
  actions.py      remoção/desativação de apps — só por pedido explícito do usuário
  devinfo.py      resumo do aparelho para o painel
  evidence.py     pasta de cada varredura: salvar, listar e carregar relatórios (com SHA256SUMS)
  util.py         utilitários compartilhados (regex de pacote, sha256 de arquivo)
  report.py       relatório HTML exportável
  apksig.py       leitura do certificado de assinatura de APKs (v1/v2/v3), só com a stdlib
  paths.py        onde ficam dados e relatórios
  web/            interface: HTML, CSS e módulos ES sem bundler (web/js/*.js)
tests/
```

## Escrevendo uma verificação

Cada arquivo em `desgrampa/checks/` expõe:

```python
NAME = "Nome exibido no painel"
CATEGORY = "intercept"         # uma das áreas em checks/__init__.py::CATEGORIES
FULL_ONLY = True               # opcional: só na varredura completa

def available(ctx):            # opcional: devolva um motivo (str) para pular
    return None

def run(ctx):
    out = ctx.try_sh("dumpsys algo")          # comandos de LEITURA; try_sh não lança exceção
    ctx.data["minha_area"] = {...}            # dados para o dashboard (opcional)
    return [Finding("alta", "Título curto", "O que foi visto e por que importa.",
                    "O que a pessoa deve fazer.", package="com.exemplo")]
```

Depois, registre o módulo em `scanner.CHECKS` (a ordem importa: `risk` fica por último).

Boas práticas:

- **Parsers como funções puras** em `context.py` ou no próprio módulo, com teste usando saída real
  anonimizada.
- **Escape tudo que vai para o shell** com `shlex.quote` quando o valor vier do aparelho ou da internet.
- **Severidade honesta.** Use `critica` só para indicador conhecido ou interceptação ativa. Heurísticas
  sozinhas ficam em `media`/`baixa`. Falso positivo crítico assusta quem já está com medo.
- **Textos em português**, claros para quem não é técnico, sempre com o “o que fazer”.
- Adicione testes em `tests/test_scan.py`. O teste `test_read_only_commands` falha se a varredura usar
  comandos de alteração.

## Interface

A interface é HTML/CSS/JS puro em `desgrampa/web`, com módulos ES carregados direto pelo navegador.
`tests/test_web.py` confere se todo `import` tem um `export` correspondente. Mantenha o padrão do
helper `el()` (nunca `innerHTML` com dados do aparelho) e use os tokens de cor de `style.css`, que
suportam tema claro e escuro.

## Pull requests

- Um assunto por PR, com testes.
- `python -m unittest` e `ruff check` passando.
- Descreva como validou: aparelho real (sem anexar dados) ou aparelho falso.
