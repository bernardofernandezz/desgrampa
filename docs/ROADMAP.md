# Roadmap

Meta: qualquer pessoa no Brasil consegue verificar, sozinha em casa ou com ajuda num ponto de
atendimento (Defensoria, DEAM, CRAM, universidade, ONG), se o celular está monitorado, invadido ou
vulnerável, com um resultado que faz sentido para quem é de TI e para quem não é.

Os princípios não mudam em nenhuma fase: **varredura somente leitura**, **nenhum dado do aparelho sai
do computador** (sem telemetria) e **todo achado explica o porquê**.

Quer ajudar? Escolha um item, abra uma issue e veja o [CONTRIBUTING.md](../CONTRIBUTING.md).

## Fase 0 — Estabilizar
- [ ] Publicar a release `v0.1.0`

## Fase 1 — Qualquer pessoa consegue instalar
- [ ] Suporte a Windows (caminhos, processos, CI em Windows e macOS)
- [ ] Executável único por sistema (PyInstaller) com o `adb` embutido
- [ ] Orientação para o driver USB no Windows
- [ ] Releases automáticas com SHA256 e assinatura (Sigstore); assinatura de código para o Windows
- [ ] Depuração sem fio (Android 11+, `adb pair`), sem precisar de cabo

## Fase 2 — Vulnerabilidades reais e dashboard para todos
- [ ] Nova área **Vulnerabilidades**:
  - [ ] CVEs dos Android Security Bulletins ainda abertas no aparelho, com destaque para as que estão
        no catálogo CISA KEV (exploradas ativamente)
  - [ ] WebView/Chrome e apps-chave desatualizados
  - [ ] Aviso de aparelho sem suporte (EOL)
- [ ] Dashboard em dois níveis:
  - [ ] **Simples** (semáforo + "o que fazer agora")
  - [ ] **Técnico** (tabela de CVEs, linha do tempo, filtros, exportação)
- [ ] Assistente de ativação da depuração USB por fabricante
- [ ] Relatório em PDF: versão pessoal e versão para atendimento/autoridade (com cadeia de custódia)
- [ ] Revisão de acessibilidade (WCAG AA) e de linguagem simples

## Fase 3 — Contexto brasileiro e segurança da vítima
- [ ] Indicadores de stalkerware vendido no Brasil (contribuídos também à AssoEchap)
- [ ] Página "Preciso de ajuda": Ligue 180, 190, Defensoria e helplines, mais um explicador legal
      (CP art. 147-A e 154-A, Lei Maria da Penha)
- [ ] Botão de saída rápida
- [ ] Modo sem rastros no computador
- [ ] Limpeza dos dados locais

## Fase 4 — Modo atendimento
- [ ] `desgrampa --atendimento`:
  - [ ] termo de consentimento
  - [ ] fila de aparelhos
  - [ ] pacote de evidências
  - [ ] limpeza automática
- [ ] Guia do operador e roteiro de acolhimento
- [ ] Piloto com 1–2 instituições

## Fase 5 — iPhone e escala
- [ ] iPhone via backup local + `mvt-ios`, no mesmo dashboard
- [ ] Atualização mensal automática da base de boletins
- [ ] Auditoria de segurança externa e modelo de ameaça publicado
- [ ] Site com download e tutoriais em vídeo; parcerias com organizações de direitos digitais
