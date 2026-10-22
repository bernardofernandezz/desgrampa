# Roadmap

Meta: qualquer pessoa no Brasil consegue verificar, sozinha em casa ou com ajuda num ponto de
atendimento (Defensoria, DEAM, CRAM, universidade, ONG), se o celular está monitorado, invadido ou
vulnerável, com um resultado que faz sentido para quem é de TI e para quem não é.

Os princípios não mudam em nenhuma fase: **varredura somente leitura**, **nenhum dado do aparelho sai
do computador** (sem telemetria) e **todo achado explica o porquê**.

Quer ajudar? Escolha um item em aberto, abra uma issue e veja o [CONTRIBUTING.md](../CONTRIBUTING.md).

## Fase 0 — Estabilizar
- [x] Revisar e commitar a refatoração pendente
- [x] Publicar a primeira release (v0.2.0)

## Fase 1 — Qualquer pessoa consegue instalar
- [x] Suporte a Windows (caminhos, processos, rede local, CI em Windows e macOS)
- [x] Executável único por sistema (PyInstaller) com o `adb` embutido
- [x] Orientação para o driver USB no Windows
- [x] Releases automáticas com SHA256, atestação Sigstore e teste de fumaça do executável em Windows, macOS e Linux
- [x] Assinatura de código no Windows: passo pronto no `release.yml`; falta enviar o [pedido à SignPath](candidaturas.md#1-signpath-foundation--assinatura-gratuita-do-executável-do-windows) e cadastrar os segredos
- [x] Depuração sem fio (Android 11+, `adb pair`), sem precisar de cabo

## Fase 2 — Vulnerabilidades reais e dashboard para todos
- [x] Área **Vulnerabilidades conhecidas**:
  - [x] boletins do Android × patch do aparelho, com destaque para o CISA KEV
  - [x] WebView/Chrome e apps de mensagem
  - [x] aparelho sem suporte (EOL)
  - [x] índice de exposição
- [x] Dashboard **simples** (semáforo + "o que fazer agora") e **técnico** (CVEs, linha do tempo, filtros,
      busca, link por achado, exportação JSON/STIX/CSV)
- [x] Assistente de ativação da depuração USB por fabricante
- [x] Relatório em PDF: versão pessoal e versão para atendimento/autoridade (cadeia de custódia)
- [x] Revisão de acessibilidade (foco visível, landmarks, pular para o conteúdo, ARIA nas abas e no semáforo)
- [ ] Teste de usabilidade com 3 a 5 pessoas não técnicas (kit pronto em [usabilidade.md](usabilidade.md))

## Fase 3 — Contexto brasileiro e segurança da vítima
- [x] Indicadores brasileiros (`dados/br-indicators.yaml`), com processo para contribuir e enviar à AssoEchap
- [x] Página "Preciso de ajuda": Ligue 180, 190, Defensoria por UF, helplines e explicador legal
- [x] Botão de saída rápida
- [x] Modo sem rastros
- [x] Limpeza dos dados locais

## Fase 4 — Modo atendimento
- [x] `desgrampa --atendimento`: termo de consentimento, fila de aparelhos, pacote de evidências, limpeza
- [x] Guia do operador e roteiro de acolhimento ([atendimento.md](atendimento.md))
- [ ] Piloto com 1 ou 2 instituições (modelo de contato em [escala.md](escala.md))

## Fase 5 — iPhone e escala
- [x] iPhone via backup local + `mvt-ios`, no mesmo dashboard
- [x] Atualização mensal automática da base de vulnerabilidades (workflow `bases.yml`)
- [x] Modelo de ameaça publicado ([modelo-de-ameaca.md](modelo-de-ameaca.md))
- [ ] Auditoria de segurança externa (pedido pronto em [candidaturas.md](candidaturas.md))
- [x] Site com download (`site/`, GitHub Pages)
- [ ] Vídeos curtos de tutorial (roteiros prontos em [videos.md](videos.md))
- [ ] Parcerias e editais (textos prontos em [candidaturas.md](candidaturas.md))

Os itens em aberto dependem de pessoas e instituições, não de código: os textos, kits e roteiros já estão prontos.

## Validação com aparelho real
- [x] Varreduras rápida e completa no Android real do mantenedor (Xiaomi, Android 12) com o executável publicado;
      corrigiu um falso positivo de processo ("gatekeeperd" tomado por Pegasus quando o SELinux nega o stat do binário)
- [ ] Depuração por Wi-Fi num aparelho real (exige parear na tela do celular)
