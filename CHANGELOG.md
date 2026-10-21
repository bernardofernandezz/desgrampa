# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/); versões seguem
[SemVer](https://semver.org/lang/pt-BR/).

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
