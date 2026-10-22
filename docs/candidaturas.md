# Candidaturas prontas para enviar

Textos para copiar nos formulários. Cada um precisa ser enviado pelo mantenedor, porque exige conta,
aceite de termos ou contato institucional.

## 1. SignPath Foundation — assinatura gratuita do executável do Windows

Formulário: https://signpath.org/apply (projetos open-source)

- **Project name:** Desgrampa
- **Repository:** https://github.com/bernardofernandezz/desgrampa
- **License:** GPL-3.0-or-later (OSI approved)
- **Description:** Desgrampa is a self-hosted tool that checks Android phones and iPhones for stalkerware,
  mercenary spyware, network interception and unpatched known-exploited vulnerabilities. It runs locally
  (127.0.0.1), never uploads device data, and is aimed at survivors of domestic abuse and at support
  services in Brazil (public defenders, women's police stations, NGOs). Windows users currently hit
  SmartScreen warnings, which is a real barrier for non-technical victims.
- **Build:** GitHub Actions (`.github/workflows/release.yml`), PyInstaller one-file executable,
  reproducible from tag, with Sigstore build-provenance attestations.
- **Artifacts to sign:** `desgrampa-windows.exe`.

Depois da aprovação:

1. Crie o projeto na SignPath com a política `release-signing`.
2. Cadastre os segredos `SIGNPATH_API_TOKEN` e `SIGNPATH_ORGANIZATION_ID` no repositório.
3. Ative o passo de assinatura do `release.yml`, que só roda quando esses segredos existem.

## 2. Auditoria de segurança — OTF Red Team Lab

Formulário: https://www.opentech.fund/labs/red-team-lab/

- **Projeto:** Desgrampa, detector de spyware e vulnerabilidades para Android/iPhone, open-source.
- **Usuários em risco:**
  - vítimas de violência doméstica monitoradas por parceiros;
  - jornalistas, ativistas e defensores de direitos humanos no Brasil.
- **Escopo pedido:**
  1. servidor local (`desgrampa/server.py`): DNS rebinding, CSRF, path traversal nos relatórios;
  2. tratamento de dados não confiáveis vindos do celular (saídas do `adb shell`, backups do iPhone) e das
     bases baixadas: injeção no shell do aparelho, XSS na interface e no relatório HTML;
  3. garantia de "somente leitura" da varredura (`tests/test_scan.py::test_read_only_commands`);
  4. modo sem rastros e modo atendimento: o que fica no disco depois de "Encerrar e apagar";
  5. cadeia de build e distribuição (PyInstaller, adb embutido, atestação Sigstore).
- **Material:** [modelo de ameaça](modelo-de-ameaca.md), [SECURITY.md](../SECURITY.md), suíte de testes offline.
- **Tamanho:** cerca de 8 mil linhas de Python e JavaScript, sem dependências além de PyYAML (e MVT, opcional).

Alternativa: [OSTIF](https://ostif.org/) (mesmo escopo).

## 3. Financiamento

### Open Technology Fund — Internet Freedom Fund
- **Problema:** no Brasil, o monitoramento por parceiros (stalkerware) é forma reconhecida de violência
  (Lei Maria da Penha, art. 7º, II; CP 147-A e 147-B). As vítimas não têm uma ferramenta gratuita, em
  português e que dispense conhecimento técnico.
- **O que já existe:**
  - Desgrampa v0.2.0 para Windows, macOS e Linux;
  - modo simples para leigos;
  - modo atendimento para Defensorias e delegacias;
  - relatório com cadeia de custódia e base legal;
  - análise de iPhone.
- **Pedido (12 meses):**
  1. pesquisa de usabilidade com vítimas e atendentes (5 cidades);
  2. pilotos em 5 instituições;
  3. auditoria;
  4. assinatura de código;
  5. indicadores brasileiros com a AssoEchap;
  6. vídeos e materiais impressos.
- **Métricas:** downloads, atendimentos registrados pelos pilotos (contagem anônima), indicadores
  publicados e tempo médio de atendimento.

### Digital Defenders Partnership / NLnet NGI Zero
O mesmo texto acima, com o foco ajustado:
- **DDP:** proteção de defensores de direitos humanos e de jornalistas (spyware mercenário, MVT,
  encaminhamento para a Access Now e o Amnesty Security Lab).
- **NLnet:** software livre de privacidade; destacar que tudo roda localmente e não há telemetria.

## 4. Parcerias de divulgação e piloto

Modelo de mensagem em [escala.md](escala.md#2-piloto-com-1-ou-2-instituições). Lista inicial:

- Coding Rights;
- InternetLab;
- SaferNet;
- Data Privacy Brasil;
- Instituto Igarapé;
- núcleos de defesa da mulher das Defensorias (NUDEM);
- núcleos de prática jurídica de universidades públicas;
- Coalizão contra o Stalkerware (pedido de adesão como membro técnico).
