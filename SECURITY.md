# Política de segurança

## Reportando uma vulnerabilidade

**Não abra issue pública** para vulnerabilidades. Use o
[relato privado do GitHub](../../security/advisories/new) (aba *Security › Report a vulnerability*).

Inclua:
- versão (`desgrampa --version`) e sistema operacional;
- passos para reproduzir e impacto esperado;
- **nenhum dado de aparelho real** (relatórios, saídas de `adb`, prints com contas ou números).

Resposta inicial em até 7 dias. Correções de segurança têm prioridade sobre qualquer outra tarefa.

## Escopo

Interessa especialmente:

- execução de comandos não intencionais no computador ou no celular (ex.: injeção via nome de pacote,
  caminho de arquivo ou base de indicadores);
- qualquer forma de a **varredura** alterar o aparelho, ou de uma remoção acontecer sem confirmação;
- acesso à API local a partir de outro site (CSRF, DNS rebinding) ou de outro computador;
- vazamento de dados do aparelho para fora da máquina;
- falsos negativos sistemáticos (spyware conhecido que não é detectado).

## Se você encontrou spyware

Este canal é para falhas **do Desgrampa**. Para ajuda com um aparelho comprometido:
- [Access Now Digital Security Helpline](https://www.accessnow.org/help/) (gratuita, em português);
- [Amnesty Security Lab](https://securitylab.amnesty.org/get-help/);
- no Brasil: Ligue 180 / 190 e [stopstalkerware.org](https://stopstalkerware.org/resources/) (em inglês).
