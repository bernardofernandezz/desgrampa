<h1 align="center">Desgrampa</h1>

<p align="center">
  <b>Detector de spyware, stalkerware e vigilância para Android — self-hosted, pelo cabo USB.</b><br>
  Painel web local · análise forense com o MVT da Anistia Internacional · nada do celular sai do seu computador.
</p>

<p align="center">
  <img src="docs/img/painel.png" alt="Painel do Desgrampa com o aparelho conectado" width="860">
</p>

> [!IMPORTANT]
> **Se você acredita que está sendo vigiado por alguém próximo**, lembre que remover um app de
> monitoramento pode alertar quem o instalou. Planeje com apoio antes: no Brasil, **Ligue 180**,
> **190** em emergência e [stopstalkerware.org](https://stopstalkerware.org/pt-br/).
> **Se suspeita de uma organização ou governo**, não apague nada e procure a
> [Access Now Digital Security Helpline](https://www.accessnow.org/help/) (gratuita, em português)
> ou o [Amnesty Security Lab](https://securitylab.amnesty.org/get-help/).

## O que é

O **Desgrampa** (de *grampo*, a gíria para escuta clandestina) conecta-se a um Android via ADB e
procura sinais de que o aparelho está sendo monitorado:

- **Stalkerware comercial**: mSpy, FlexiSPY, TheTruthSpy, Cerberus e outros. Compara nome, certificado e hash
  de cada app com ~650 pacotes, ~490 certificados e ~3.400 amostras conhecidas.
- **Spyware mercenário/estatal**: indicadores de Pegasus, Predator, Candiru, NoviSpy, Cellebrite, RCS Lab
  e outros. Na varredura completa, gera um bugreport e o analisa com o
  [MVT](https://github.com/mvt-project/mvt).
- **Interceptação de conexões**: certificados de segurança instalados, certificados injetados no sistema,
  proxy (global, por Wi-Fi e na conexão ativa), VPN, DNS privado e teste de DNS feito pelo próprio celular.
- **Rede local** (opcional, a partir do computador): DNS adulterado, HTTPS interceptado, proxy transparente
  e ARP spoofing.
- **Telefonia**: desvio de chamadas, rede 2G (ERB falsa), rede estrangeira sem roaming e apps que controlam
  SMS ou ligações.
- **Contas e perfis**: contas Google de terceiros, contas criadas por apps suspeitos e apps escondidos em
  perfis de trabalho, Pasta Segura ou apps duplicados.
- **Controle remoto**: administradores do aparelho, MDM, apps de acesso remoto e de rastreamento.
- **Rastros**: apps de espionagem que já foram desinstalados (histórico de bateria, estatísticas de uso,
  logs, pastas que sobraram) e endereços de spyware citados nos logs.
- **Integridade**: root, bootloader, dm-verity, SELinux, firmware assinado com chaves públicas de teste
  do AOSP, permissões privilegiadas concedidas via cabo e apps de sistema falsos.

O resultado aparece num **dashboard**: veredito, 12 áreas analisadas, achados agrupados por
**categoria → origem** (ex.: `Life360 (30) → 10 críticos · 10 altos · 5 médios · 5 baixos`), dados
de rede/telefonia/contas e um checklist do que só dá para conferir na nuvem ou na operadora.

<p align="center"><img src="docs/img/resultado.png" alt="Resultado com achados agrupados e ações sugeridas" width="860"></p>

## Princípios

- **A varredura é somente leitura.** Ela só executa comandos de consulta no celular; um teste automatizado
  garante que nenhum comando de alteração é usado.
- **Remoção só com confirmação manual.** Apps com achado crítico ou de spyware aparecem como *sugestão*. Para
  remover ou desativar, você confirma os riscos e digita o nome do pacote. Antes de qualquer alteração, uma
  cópia do APK é guardada como evidência, e toda ação fica registrada.
- **Self-hosted.** O painel roda só em `127.0.0.1`. Dados do celular (apps, contas, relatórios) nunca são
  enviados para lugar nenhum.
- **Evidência preservada.** Cada varredura salva a saída bruta de todos os comandos, o bugreport, o resultado
  do MVT e um `SHA256SUMS.txt`, pronto para entregar a um laboratório forense.

### O que acessa a internet

Por transparência, estas são as únicas conexões feitas pelo **computador**:

| Quando | Para quê | Destino |
|---|---|---|
| Primeira execução / “Atualizar bases” | baixar as bases de indicadores | `raw.githubusercontent.com` |
| Teste de DNS (todas as varreduras) | resposta de referência para domínios de teste | `cloudflare-dns.com` (DNS-over-HTTPS) |
| Teste de rede local (opcional) | testar DNS/HTTPS/proxy da sua rede | sites públicos como `google.com`, `example.com` e `cloudflare.com` |

O celular também resolve alguns domínios públicos de teste durante o teste de DNS.

## Instalação

Requisitos: **Python 3.10+** e **adb** (Android platform-tools).

```bash
# adb
sudo pacman -S android-tools        # Arch
sudo apt install adb                # Debian/Ubuntu
brew install android-platform-tools # macOS

# Desgrampa (com o MVT para a varredura completa)
pipx install "desgrampa[forense] @ git+https://github.com/bernardofernandezz/desgrampa"
```

<details>
<summary>A partir do código-fonte</summary>

```bash
git clone https://github.com/bernardofernandezz/desgrampa && cd desgrampa
python -m venv .venv
.venv/bin/pip install -e ".[forense]"
.venv/bin/desgrampa
```

Rodando a partir do clone, bases e relatórios ficam em `data/` e `relatorios/` dentro do repositório
(ambos ignorados pelo git).
</details>

## Uso

```bash
desgrampa                      # abre o painel em http://127.0.0.1:8765
desgrampa --port 9000 --no-browser
desgrampa atualizar-bases      # baixa ou atualiza as bases de indicadores
```

No celular:
1. Toque 7 vezes em **Configurações › Sobre o telefone › Número da versão** para liberar as opções do
   desenvolvedor.
2. Ative a **Depuração USB**. Em aparelhos Xiaomi, ative também “Depuração USB (configurações de segurança)”.
3. Conecte o cabo e toque em **Permitir** no aviso do celular.
4. Escolha a varredura **Rápida** (1–2 min) ou **Completa/forense** (10–25 min) e clique em **Iniciar**.
5. Ao terminar, **desligue a depuração USB**.

Os dados ficam em `~/.local/share/desgrampa` (ou em `$DESGRAMPA_HOME`). Os relatórios contêm
informações pessoais do aparelho: **não os publique**.

| Variável | Uso |
|---|---|
| `DESGRAMPA_HOME` | pasta de dados (bases e relatórios) |
| `DESGRAMPA_ADB` | caminho do `adb`, se não estiver no PATH |
| `DESGRAMPA_MVT` | caminho do `mvt-android`, se não estiver no mesmo ambiente |

## Limitações (leia antes de confiar no resultado)

- **Nenhuma ferramenta prova que um aparelho está limpo.** Os indicadores só reconhecem o que já foi
  documentado, e spyware de clique zero pode não deixar rastros acessíveis por ADB.
- Sem root, os certificados instalados pelo usuário só são detectados de forma indireta (pelo aviso
  “a rede pode estar sendo monitorada” e pelas políticas de MDM).
- Interceptação na operadora (fora o 2G) e contas invadidas na nuvem não aparecem pelo cabo. Por isso
  existe a aba **Verificações manuais**.
- Alguns achados são heurísticos e podem gerar falsos positivos. Cada um explica o motivo; leia antes de agir.
- Só Android. Para iPhone, use o [MVT](https://docs.mvt.re) diretamente.

## Desenvolvimento

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m unittest -v      # roda offline, com bases de indicadores mínimas em tests/fixtures
.venv/bin/ruff check desgrampa tests
```

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para a estrutura do projeto e como escrever uma nova verificação.
Vulnerabilidades: [SECURITY.md](SECURITY.md).

## Créditos

- Indicadores de stalkerware: [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)
  ([CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/)).
- Indicadores de spyware mercenário: [mvt-project/mvt-indicators](https://github.com/mvt-project/mvt-indicators),
  que reúne investigações da Anistia Internacional, Citizen Lab, Google TAG, Meta, Lookout e outros.
- Análise forense: [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) (Anistia Internacional),
  usado como ferramenta externa, sem código incorporado.

As bases são baixadas das fontes originais e não são redistribuídas por este repositório.

## Licença

[GPL-3.0-or-later](LICENSE). Versões modificadas distribuídas a terceiros precisam continuar abertas.

---

<details>
<summary><b>English</b></summary>

**Desgrampa** is a self-hosted Android spyware and surveillance scanner. Plug a phone in over USB (ADB) and
it checks for commercial stalkerware and mercenary spyware indicators (AssoEchap + MVT/Amnesty
indicators), runs the Amnesty International MVT on a bugreport, and looks for TLS interception
certificates, proxies, DNS tampering, call forwarding, 2G downgrades, hidden profiles, remote-access
and tracking apps, traces of uninstalled spyware and firmware integrity issues. Results are shown in a
local web dashboard (Brazilian Portuguese UI) and saved with hashed evidence. Scans are read-only, and
app removal only happens after explicit manual confirmation. Install with
`pipx install "desgrampa[forense] @ git+https://github.com/bernardofernandezz/desgrampa"` and run `desgrampa`.
Licensed under GPL-3.0-or-later.
</details>
# desgrampa
