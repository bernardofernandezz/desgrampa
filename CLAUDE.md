# CLAUDE.md — Desgrampa

Detector self-hosted de spyware, stalkerware, invasão e vulnerabilidades para Android (via ADB) e iPhone (via backup + MVT). Painel web local em `127.0.0.1`, UI em português do Brasil. Licença GPL-3.0-or-later. Versão atual: 0.2.0 (Beta).

O público inclui pessoas em situação de risco (violência doméstica, perseguição, jornalistas, ativistas). Isso define as prioridades do projeto: segurança de quem usa vem antes de qualquer conveniência.

## Postura de trabalho (leia antes de responder)

O objetivo é me ajudar a **decidir bem** e a escrever código e arquitetura **enxutos, seguindo boas práticas**. Não é me dar razão.

### Como lidar com as minhas propostas

- **Não concorde de cara.** Toda proposta minha (ideia, abordagem, refactor, nova dependência, mudança de arquitetura, "e se a gente...") passa por avaliação antes da resposta. Pergunte-se: o problema é real? Existe uma solução mais simples? Quais os custos (complexidade, manutenção, segurança, privacidade, compatibilidade Linux/macOS/Windows)? Isso encosta nas regras inegociáveis?
- **Concorde só depois de ponderar e só se achar o caminho viável.** Quando concordar, diga em uma ou duas frases por quê e aponte as ressalvas que importam. Sem elogio vazio ("ótima ideia!").
- **Quando discordar, diga claramente.** Dê o motivo concreto e proponha uma alternativa. Se for um trade-off legítimo, mostre as opções com prós e contras e recomende uma.
- **Não discorde por reflexo.** Se a ideia é boa, diga isso direto. Discordância precisa de argumento técnico, não de ritual.
- **Pergunte pelo problema por trás do pedido** quando a solução parecer desproporcional. Uma pergunta por vez, e só se a resposta mudar a recomendação.
- **Verifique antes de afirmar.** Leia o código e os testes relevantes antes de opinar. Não invente APIs, funções ou comportamento. Se não souber ou não tiver certeza, diga.
- **Se eu insistir após uma objeção fundamentada**, a decisão é minha e não viola as regras inegociáveis: siga, registrando em uma linha o risco assumido. Se violar as regras inegociáveis, não implemente até eu confirmar explicitamente que quero mudar a regra (e, nesse caso, atualize este arquivo).

### Como escrever código e desenhar arquitetura

- **A menor mudança que resolve o problema** (KISS, YAGNI). Sem abstração, camada ou configuração "para o futuro".
- **Prefira stdlib e o que já existe no repo.** Dependência nova exige justificativa explícita.
- **Funções pequenas e puras, testáveis offline.** Um módulo, uma responsabilidade. Siga o padrão dos arquivos vizinhos antes de inventar um novo.
- **Trate erros nas fronteiras** (adb, rede, parsing de saída do aparelho, entrada do usuário) e não engula exceções.
- **Toda mudança de comportamento vem com teste.**
- **Sem código morto, sem comentário que repete o código, sem refactor fora do escopo.** Se enxergar algo fora do escopo que valha a pena, aponte em vez de mexer.
- **Seja conciso.** Vá direto ao ponto, sem repetir o que já foi dito e sem despejar alternativas que você não recomendaria.

## Regras inegociáveis

1. **A varredura nunca altera o aparelho.** Verificações só executam comandos de leitura. Alterar apps existe apenas em `desgrampa/actions.py` (`restrict` = cortar acessos, `disable`, `uninstall`, `enable`), e só para apps sugeridos no relatório (`removal_candidates`), com consentimento explícito na interface — pelo assistente de um app ou pelo plano de limpeza. O servidor (`post_action`) exige: remover → nome do pacote digitado (ou `REMOVER` digitado uma vez no plano de limpeza); ações reversíveis → `consent: true`; spyware mercenário → ciência extra (`mercenary_ack`). Por padrão o APK é guardado como evidência antes, e toda ação vai para `acoes.jsonl` com o motivo e a origem (plano/individual). O teste `test_read_only_commands` falha se a varredura usar comando de alteração; nunca o enfraqueça (pode ampliar a lista).
2. **Privacidade em primeiro lugar.** Dados do celular (apps, contas, relatórios) nunca saem do computador. O painel escuta só em `127.0.0.1`. Nunca adicione telemetria, analytics, CDN externo ou chamada de rede nova sem atualizar a tabela "O que acessa a internet" do README. Hoje as únicas conexões são: `raw.githubusercontent.com` (bases), `cloudflare-dns.com` (DoH) e sites públicos no teste de rede local opcional.
3. **Nunca use dados reais de aparelho** em testes, issues, PRs, commits ou exemplos. Use `tests/fake_device.py` e `tests/fixtures/iocs`. Relatórios contêm informações pessoais e não devem ser publicados.
4. **Severidade honesta.** `critica` só para indicador conhecido (IOC) ou interceptação ativa. Heurísticas sozinhas ficam em `media`/`baixa`. Falso positivo crítico assusta quem já está com medo.
5. **Nenhuma ferramenta prova que um aparelho está limpo.** Mantenha essa honestidade nos textos, no veredito e nas limitações do README.

## Comandos

```bash
# Ambiente
python -m venv .venv
.venv/bin/pip install -e ".[dev,forense]"      # forense = MVT; dev = ruff; empacotar = pyinstaller

# Rodar
.venv/bin/desgrampa                             # painel em http://127.0.0.1:8765
.venv/bin/desgrampa --sem-rastros               # relatórios em pasta temporária
.venv/bin/desgrampa --atendimento               # modo para Defensorias/delegacias/apoio
.venv/bin/desgrampa --port 9000 --no-browser
.venv/bin/desgrampa atualizar-bases             # baixa bases de indicadores e vulnerabilidades

# Testes e lint (rodam offline)
.venv/bin/python -m unittest -v
.venv/bin/ruff check desgrampa tests

# Executável único (PyInstaller, com adb embutido)
python packaging/baixar_adb.py && pyinstaller packaging/desgrampa.spec
```

Antes de dar uma tarefa por concluída: `unittest` e `ruff check` precisam passar.

Variáveis de ambiente: `DESGRAMPA_HOME` (dados/relatórios), `DESGRAMPA_ADB` (caminho do adb; tem prioridade sobre o adb embutido e o do PATH), `DESGRAMPA_MVT` / `DESGRAMPA_MVT_IOS`. Os testes não usam adb: simulam o aparelho com `tests/fake_device.py` (e `mock` em `server.adb`).

## Arquitetura

Pacote Python em `desgrampa/` (Python >= 3.10, única dependência de runtime: `pyyaml`; `mvt` é opcional via extra `forense`).

```
desgrampa/
  cli.py          comando `desgrampa` (também `python -m desgrampa`, via __main__.py)
  adb.py          chamadas ao adb (lista de aparelhos, shell, pull, bugreport)
  server.py       servidor HTTP local (127.0.0.1) e API usada pela interface
  scanner.py      orquestra as verificações, calcula o veredito, salva evidências (CHECKS; `risk` fica por último);
                  on_check alimenta o progresso ao vivo por verificação no painel
  context.py      coleta de dados do aparelho (com cache) e parsers das saídas do adb
  checks/         uma verificação por arquivo; categorias em checks/__init__.py::CATEGORIES
  iocs.py         bases de indicadores (AssoEchap + STIX2 do MVT)
  grouping.py     agrupamento categoria → origem e sugestões (level "ameaca" ou "revisar"); roda também ao carregar
                  relatórios antigos (evidence.load)
  explain.py      textos em linguagem simples: o que cada app consegue fazer, por que foi apontado, ação recomendada
  actions.py      cortar acessos/desativar/remover/reativar apps — SÓ por pedido explícito do usuário
  devinfo.py      resumo do aparelho para o painel
  evidence.py     pasta de cada varredura (salvar/listar/carregar, SHA256SUMS)
  report.py       relatório HTML exportável
  export.py       STIX 2.1 e CSV
  apksig.py       certificado de assinatura de APK (v1/v2/v3), só stdlib
  bulletins.py    base de vulnerabilidades Android/iOS (gerada por tools/build_bulletins.py)
  ios.py          iPhone: backup local + MVT + versão do iOS
  ajuda.py        rede de apoio e base legal (dados/ajuda.json)
  atendimento.py  modo atendimento: termo, nº de atendimento, pacote, limpeza
  paths.py        onde ficam dados e relatórios
  oscompat.py     diferenças Linux/macOS/Windows; adb embutido no executável
  util.py         utilitários (regex de pacote, sha256)
  dados/          bases versionadas: android_bulletins.json, br-indicators.yaml, ajuda.json
  web/            interface: HTML, CSS e módulos ES sem bundler (web/js/*.js)
tools/            build_bulletins.py (roda todo mês no CI)
packaging/        PyInstaller + download do adb
site/             página de download (GitHub Pages)
docs/             atendimento.md, modelo-de-ameaca.md, indicadores-br.md, ROADMAP.md, escala.md, candidaturas.md,
                  usabilidade.md, videos.md
tests/            test_scan (verificações), test_actions (sugestões e ações), test_server (API), test_web (módulos JS),
                  test_vulns, test_ios, test_br, test_devinfo, test_platform; fake_device.py e fixtures/
```

Se adicionar arquivos que precisam ir no pacote (HTML/CSS/JS/JSON/YAML), confira `[tool.setuptools.package-data]` no `pyproject.toml`.

## Como escrever uma verificação

Cada arquivo em `desgrampa/checks/` expõe:

```python
NAME = "Nome exibido no painel"
CATEGORY = "intercept"        # uma das áreas de checks/__init__.py::CATEGORIES
FULL_ONLY = True              # opcional: só na varredura completa

def available(ctx):           # opcional: devolva um motivo (str) para pular
    return None

def run(ctx):
    out = ctx.try_sh("dumpsys algo")     # comandos de LEITURA; try_sh não lança exceção
    ctx.data["minha_area"] = {...}       # dados para o dashboard (opcional)
    return [Finding("alta", "Título curto", "O que foi visto e por que importa.",
                    "O que a pessoa deve fazer.", package="com.exemplo")]
```

Depois registre o módulo em `scanner.CHECKS` (a ordem importa).

Boas práticas:

- Parsers como **funções puras** (em `context.py` ou no módulo), testados com saída real **anonimizada**.
- Escape tudo que vai para o shell com `shlex.quote` quando o valor vier do aparelho ou da internet.
- Textos em português, claros para quem não é técnico, sempre com o "o que fazer".
- Adicione testes em `tests/test_scan.py`.
- Achado com `package` e severidade alta/crítica vira sugestão de ação (grouping.py). Se a verificação traz um novo tipo
  de capacidade ou sinal, traduza-o em `explain.py` para que a explicação ao usuário continue completa.

## Interface (`desgrampa/web`)

- HTML/CSS/JS puro, módulos ES carregados direto pelo navegador, **sem bundler e sem framework**. Não introduza build step.
- Use o helper `el()` para montar DOM. **Nunca `innerHTML` com dados vindos do aparelho** (risco de XSS com conteúdo controlado por um app malicioso).
- Use os tokens de cor de `style.css` (suportam tema claro e escuro).
- `tests/test_web.py` confere que todo `import` tem um `export` correspondente.
- Dois modos de visualização: **Simples** (padrão, leigos: semáforo, índice de exposição, painel de ameaças, "o que fazer agora") e **Técnico** (categoria → origem, CVEs, linha do tempo). Mudanças devem respeitar os dois.
- Ações sobre apps ficam em `web/js/actions.js`: cartão de cada app com a explicação (`explain`), assistente de um app (segurança → o que fazer → confirmar → resultado) e plano de limpeza. Não pule a etapa de segurança nem pré-marque spyware mercenário.
- Alguns textos existem em Python e em JS (nomes das áreas e gravidade em palavras: `explain.AREAS`/`SEVERITY_PLAIN` e `web/js/simple.js`; `PLAN_CONFIRM` em `server.py` e `actions.js`). Mude os dois juntos.
- Recursos de segurança da pessoa que usa: "Sair rápido" (ou Esc duas vezes), `--sem-rastros`, "Apagar tudo", página "Preciso de ajuda". Não remova nem esconda.

## Convenções

- **Idioma:** textos de UI, mensagens de achado, docs e commits em português do Brasil; identificadores de código em inglês ou no padrão já usado no arquivo.
- **Ruff:** `line-length = 120`, `target-version = py310`, regras `E,F,W,B,UP,SIM,I` (ignora `E501,B904,SIM102,SIM108,UP015`).
- Compatível com Linux, macOS e Windows: diferenças de plataforma ficam em `oscompat.py`/`paths.py`.
- Não incorpore código do MVT; ele é usado como ferramenta externa (licença/atribuição). Bases de indicadores são baixadas das fontes originais e **não são redistribuídas**, exceto `android_bulletins.json` e `br-indicators.yaml` (CC-BY 4.0 com atribuição, AssoEchap). Preserve os créditos.
- Citações legais (CP 147-A, 147-B, 154-A; Lei 9.296 art. 10; Lei 12.737; Lei Maria da Penha art. 7º, II; CPP 158-A a 158-F) vivem em `dados/ajuda.json`; não altere sem conferir o texto da lei.
- Mudanças relevantes entram no `CHANGELOG.md`. Vulnerabilidades do próprio projeto: veja `SECURITY.md`.

## Commits e Pull Requests

### Autoria
- **Nunca** adicione Claude (ou qualquer IA) como coautor. Não inclua trailers `Co-Authored-By:` nem linhas como "Generated with Claude Code", nem nos commits nem na descrição de PRs.
- A autoria é sempre da pessoa que está commitando.

### Formato (Conventional Commits)
```
<tipo>(<escopo opcional>): <descrição curta no imperativo>

<corpo opcional: o que mudou e, principalmente, por quê>
```

- **Tipos:** `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`.
- **Escopos sugeridos:** `checks`, `scanner`, `web`, `ios`, `server`, `actions`, `bulletins`, `atendimento`, `packaging`, `site`, `docs`.
- **Descrição:** em português, minúscula, sem ponto final, até ~72 caracteres. Ex.: `fix(checks): ignora falso positivo de proxy em rede corporativa`.
- **Breaking changes:** use `!` após o tipo/escopo (`feat(server)!: ...`) e explique no corpo.

### Organização
- **Um commit = uma mudança lógica.** Não misture correção, refatoração e formatação no mesmo commit.
- Cada commit deve deixar `python -m unittest` e `ruff check desgrampa tests` passando.
- Testes e código que eles cobrem vão no mesmo commit.
- Nunca inclua dados reais de aparelho (nomes de apps pessoais, contas, saídas de `adb`) em mensagens de commit ou PR.

### Pull Requests
- Um assunto por PR; o título segue o mesmo padrão Conventional Commits.
- A descrição diz o que mudou, por que mudou e como foi validado (aparelho real sem anexar dados, ou `tests/fake_device.py`).
- Registre mudanças relevantes para o usuário no `CHANGELOG.md`.

## Cuidados ao trabalhar neste repo

- Não rode comandos `adb` de alteração (`pm uninstall`, `pm disable`, `pm revoke`, `settings put`, `cmd appops set`, `rm`, etc.) fora de `actions.py`.
- `relatorios/` (se existir na raiz) contém dados reais de aparelho: nunca versione, publique nem use em capturas de tela.
- Não adicione dependências de runtime sem forte motivo; o projeto prefere stdlib (ex.: `apksig.py`) e `pyyaml` apenas.
- Ao mexer em achados/veredito, pense em quem lê: alguém possivelmente assustado, sem conhecimento técnico, que pode estar sendo vigiado por uma pessoa próxima. Remover um app de monitoramento pode alertar quem o instalou; os textos de ação devem refletir isso.