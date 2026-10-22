# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/); versões seguem
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado
- **Progresso ao vivo da varredura**: lista das 21 verificações com estado (aguardando, em andamento,
  concluída, não executada, falhou), achados por verificação, tempo decorrido e o que já foi encontrado
  (críticos primeiro).
- **Cortar acessos**: nova ação que tira acessibilidade, leitura de notificações, permissões perigosas
  (SMS, ligações, microfone, câmera, localização…), gravação/sobreposição de tela e execução em segundo
  plano, e para o app — sem desinstalar, preservando as evidências. **Reativar** desfaz uma desativação.
- **Apps para revisar**: apps instalados pelo usuário com achado alto (ex.: acessibilidade) também podem
  ser tratados, separados das ameaças confirmadas.
- **Explicação de cada app suspeito** (`explain.py`): o que é (stalkerware, spyware mercenário, app de
  monitoramento…), por que foi apontado, o que ele consegue fazer no celular (por tema: mensagens, tela,
  localização…), grau de certeza e a ação recomendada com o motivo.
- **Plano de limpeza**: o Desgrampa propõe uma ação para cada app (pré-marcando só espionagem clara, nunca
  spyware mercenário), o usuário revisa, autoriza (digitando REMOVER se houver remoções) e acompanha a
  execução item a item. Cada ação fica registrada com o motivo e a origem (plano ou individual).

### Alterado
- **Relatório HTML mais fácil de entender**: começa com o resumo em linguagem simples, as 13 áreas como
  perguntas do dia a dia, os apps suspeitos explicados, o que fazer agora e as alterações feitas (com o
  motivo); os detalhes técnicos vêm depois. Gravidade em palavras ("Grave", "Preocupante"…).
- Alertas do MVT ligados a stalkerware comum (ex.: Life360) não são mais classificados como spyware
  mercenário (também corrigido na leitura de relatórios antigos).
- Painel de ameaças redesenhado e mostrado logo abaixo do semáforo no modo simples, com o estado de cada
  app (restrito, desativado, removido) e o histórico de ações.
- Assistente de ação em etapas (segurança → o que fazer → confirmar → resultado, com os comandos
  executados). Remover continua exigindo o nome do pacote digitado; as ações reversíveis exigem
  autorização explícita (`consent`); spyware mercenário exige ciência extra em toda alteração.

## [0.2.0] — uso nacional

### Adicionado
- **Windows e macOS**: executável único por sistema com o `adb` embutido (PyInstaller), pastas de dados
  nativas, teste de rede local no Windows/macOS e CI nos três sistemas. Releases com `SHA256SUMS.txt` e
  atestação de proveniência Sigstore.
- **Depuração por Wi-Fi** (Android 11+) e guia de ativação da depuração USB por fabricante, com dicas de
  driver no Windows.
- **Vulnerabilidades conhecidas** (nova área): falhas dos boletins de segurança do Android abertas no
  aparelho, destaque para as exploradas ativamente (CISA KEV), versão sem suporte, Chrome/WebView e apps de
  mensagem desatualizados e índice de exposição. Base gerada por `tools/build_bulletins.py` e atualizada
  todo mês por um workflow.
- **Dashboard em dois modos**: simples (semáforo, o que fazer agora, áreas em linguagem do dia a dia) e
  técnico (tabela de CVEs com filtros, linha do tempo, busca e link direto para cada achado).
- Relatório para **imprimir/PDF**, relatório **para atendimento/autoridade** (hashes, cadeia de custódia e
  base legal), pacote de evidências `.zip`, exportação STIX 2.1 e CSV.
- Página **Preciso de ajuda**: Ligue 180, Defensoria Pública por estado, como guardar provas e legislação
  (CP 147-A, 147-B, 154-A; Lei 9.296, art. 10; Lei Maria da Penha, art. 7º, II; CPP 158-A).
- **Segurança de quem usa**: botão "Sair rápido" (e Esc duas vezes), modo sem rastros (`--sem-rastros`) e
  "Apagar tudo".
- **Modo atendimento** (`--atendimento`): termo de consentimento, número de atendimento, pacote de
  evidências e limpeza do computador; guia do operador em `docs/atendimento.md`.
- **Indicadores brasileiros** (`dados/br-indicators.yaml`): famílias vendidas no Brasil, com a menção ao
  art. 154-A, § 1º, nos achados.
- **iPhone**: backup local (pelo cabo com libimobiledevice ou pasta do Finder/iTunes) analisado pelo
  `mvt-ios`, perfis de configuração e versão do iOS × falhas da Apple exploradas ativamente.
- Site de download (GitHub Pages), modelo de ameaça e plano de escala.

### Corrigido
- Duas varreduras no mesmo segundo não sobrescrevem mais a mesma pasta de evidências.
- `adb` configurado num caminho inexistente não derruba mais o painel.
- Link quebrado para a Coalizão contra o Stalkerware.

## [0.1.0] — primeira versão pública

### Adicionado
- Painel web local (127.0.0.1) com cartão do aparelho lido pelo USB: modelo, Android/ROM, patch, chip,
  operadora, armazenamento, bateria, bootloader e outros.
- Varredura rápida e completa (forense) em 12 áreas: stalkerware, spyware mercenário, interceptação de
  conexões, rede do aparelho, rede local, telefonia, contas e perfis, controle remoto, rastros,
  integridade do sistema, apps e permissões e proteções.
- Bases de indicadores AssoEchap e mvt-indicators (STIX2), baixadas na primeira execução.
- Integração opcional com o MVT (`desgrampa[forense]`) sobre o bugreport do aparelho.
- Achados agrupados por categoria → origem, com contagem por severidade.
- Sugestões de remoção/desativação com confirmação manual, cópia do APK como evidência e registro em
  `acoes.jsonl`.
- Evidências por varredura: comandos brutos, relatório HTML/JSON, bugreport, saída do MVT e `SHA256SUMS.txt`.
- Comando `desgrampa` e `desgrampa atualizar-bases`.
