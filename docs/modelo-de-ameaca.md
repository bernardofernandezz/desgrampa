# Modelo de ameaça

O que o Desgrampa protege, de quem e o que fica de fora. Serve para quem audita o código e para
quem decide se a ferramenta serve ao seu caso.

## Quem usa e contra quem

| Pessoa | Adversário típico | O que o Desgrampa faz |
|---|---|---|
| Vítima de violência doméstica | Parceiro(a) ou ex com acesso físico ao celular e senha | Detecta stalkerware comercial, permissões dadas pelo cabo, contas e perfis extras, desvio de chamadas e rastros de apps já removidos |
| Jornalista, ativista, advogado(a) | Spyware mercenário (Pegasus, Predator…) | Compara com os indicadores da Anistia/Citizen Lab, roda o MVT e mostra falhas exploradas ativamente ainda abertas |
| Qualquer pessoa | Golpistas e redes adulteradas | Detecta proxy, certificados instalados, DNS adulterado, ARP spoofing e apps fora da loja |
| Ponto de atendimento | Vazamento dos dados de quem foi atendido | Modo atendimento: pasta temporária, termo, pacote entregue e limpeza |

## Ativos

1. **Os dados do celular**: lista de apps, contas, redes Wi-Fi, logs e o bugreport (que inclui
   mensagens do sistema).
2. **As evidências**: precisam continuar íntegras para uso jurídico.
3. **A segurança física da pessoa**: remover um app pode alertar quem o instalou.
4. **O computador** onde o Desgrampa roda.

## Garantias

- **A varredura é somente leitura.** Os comandos de `adb shell` vêm de uma lista fechada de
  consultas; `tests/test_scan.py::test_read_only_commands` falha se um comando de alteração
  aparecer. Remover ou desativar um app é uma ação separada (`actions.py`), que exige:
  - que o app esteja entre as sugestões do relatório;
  - que a pessoa digite o nome do pacote;
  - para spyware mercenário, que ela confirme que entende o risco.

  Antes de qualquer alteração, o APK é copiado como evidência.
- **Nada sai do computador.** O servidor escuta só em `127.0.0.1`, recusa `Host` diferente (contra
  DNS rebinding) e exige `Content-Type: application/json` nos POSTs (contra CSRF via formulário).
  As únicas conexões externas são para baixar as bases e para os testes de DNS/HTTPS (lista no
  README).
- **Integridade das evidências.** Cada pasta tem `SHA256SUMS.txt`. O relatório para atendimento traz
  o hash do `relatorio.json` e do `SHA256SUMS.txt`, além de uma tabela de cadeia de custódia (CPP,
  arts. 158-A a 158-F).
- **Sem rastros, quando pedido.**
  - `--sem-rastros` e `--atendimento` guardam os relatórios numa pasta temporária, apagada ao sair.
    Pastas de sessões que caíram são apagadas depois de 12 h.
  - "Apagar tudo" remove os relatórios e limpa o armazenamento do navegador.
  - "Sair rápido" troca a página por um site neutro sem deixar o painel no histórico de "voltar".
- **Distribuição verificável.** As releases são compiladas no GitHub Actions a partir da tag, com
  `SHA256SUMS.txt` e atestação de proveniência Sigstore
  (`gh attestation verify <arquivo> --repo bernardofernandezz/desgrampa`).

## O que fica de fora (limites conhecidos)

- **Não prova que o aparelho está limpo.** Indicadores só reconhecem o que já foi documentado, e
  spyware de clique zero pode não deixar rastro acessível por ADB ou por backup.
- **Root/jailbreak do adversário:**
  - um spyware com root pode mentir para o `adb shell`;
  - o Desgrampa detecta sinais de root (su, Magisk, bootloader, dm-verity), mas não consegue
    inspecionar um sistema já comprometido no kernel.
- **Nuvem e operadora.** Conta Google/iCloud invadida, encaminhamento de e-mail, SIM swap e
  interceptação na operadora (fora o 2G) não aparecem pelo cabo. Para isso existe a lista de
  verificações manuais.
- **Base de vulnerabilidades parcial:**
  - cobre os boletins do Android (AOSP, kernel, Qualcomm e Pixel) e as falhas exploradas da CISA;
  - **não** cobre os boletins próprios de Samsung, Motorola e Xiaomi, nem chips MediaTek, Exynos e
    Unisoc. O número real de falhas pode ser maior.
- **Computador comprometido.** Se o computador onde o Desgrampa roda tiver malware, ele pode ver os
  dados coletados. Em atendimento, use um computador dedicado e atualizado.
- **Depuração USB ligada.** Enquanto está ligada, ela também é uma porta de entrada. O Desgrampa
  lembra de desligá-la no fim, mas não consegue desligá-la sozinho, porque a varredura é somente
  leitura.
- **Coerção.** Se o adversário obriga a pessoa a desbloquear o celular, nenhuma ferramenta resolve.
  Por isso o foco do modo atendimento é o acolhimento e o plano de segurança.

## Superfície de ataque do próprio Desgrampa

| Entrada | Risco | Mitigação |
|---|---|---|
| Saídas do `adb shell` (controladas pelo celular, possivelmente por um spyware) | Injeção na interface ou no relatório | A interface nunca usa `innerHTML` com dados do aparelho (`el()` cria nós de texto); o relatório HTML escapa tudo com `html.escape` |
| Nomes de pacote e caminhos vindos das bases baixadas | Injeção de comando no `adb shell` | `shlex.quote` em todo valor externo (`test_paths_from_downloaded_bases_are_shell_quoted`) |
| API local | Outro site ou outro computador acionando a API | Escuta só em `127.0.0.1`, checa `Host` e exige JSON |
| Nome de relatório na URL | Path traversal | `evidence.report_path` aceita só `[\w.-]+` e confirma que o caminho resolvido está dentro da pasta de relatórios |
| Bases de indicadores e de vulnerabilidades | Base adulterada | Baixadas por HTTPS de GitHub/CISA/Google/Apple; o gdmf da Apple é validado com a Apple Root CA baixada de apple.com |
| Depuração por Wi-Fi | Pareamento com um aparelho de outra rede | Aceita só IPv4 de rede privada e código de 6 dígitos; a interface pede para desligar no fim |

## Como reportar

Veja [SECURITY.md](../SECURITY.md). Falhas que quebrem as garantias acima têm prioridade sobre
qualquer outra tarefa.
