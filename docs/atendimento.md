# Guia do modo atendimento

Para Defensorias Públicas, Delegacias de Defesa da Mulher, CRAMs, Casas da Mulher Brasileira,
núcleos de prática jurídica de universidades e ONGs que querem verificar o celular das pessoas
atendidas.

## O que você precisa

- Um computador (Windows, macOS ou Linux) com o Desgrampa. Prefira um computador que fique na
  instituição e não seja usado para outras coisas.
- Cabos USB **de dados**: um USB-C e um micro-USB (e um Lightning, para iPhone).
- Pendrives novos para entregar o pacote de evidências a quem for atendido.
- Opcional, para a varredura completa (forense): o MVT (`pipx install "desgrampa[forense]"`).
- Para iPhone: o libimobiledevice (no Linux e no macOS) ou o iTunes/Dispositivos Apple (no Windows).

Inicie sempre assim:

```bash
desgrampa --atendimento
```

No executável do Windows, crie um atalho com `--atendimento` no fim do campo "Destino".

Nesse modo:

- os relatórios ficam numa pasta temporária, apagada quando o programa fecha;
- nenhuma varredura começa sem um atendimento aberto com o termo de consentimento;
- cada atendimento recebe um número (`ATD-AAAAMMDD-NNN`), que vai no nome das pastas de evidências;
- no fim, você baixa o pacote do atendimento e, ao encerrar, os dados são apagados do computador.

## Roteiro

### 1. Acolhimento (antes de tocar no celular)

- Escute sem julgar. Frases que ajudam: "O que fez você desconfiar?", "Você está em segurança agora?",
  "Essa pessoa costuma mexer no seu celular?".
- Explique o que vai acontecer: a verificação **só lê** o celular, não apaga nada e leva de 2 a 25
  minutos.
- Pergunte se é seguro ela voltar para casa com o celular. Se quem instalou o app perceber que ele
  foi removido, pode reagir. **Nada é removido sem um plano de segurança.**
- Em risco imediato, ligue 190. Para violência contra a mulher, ofereça o Ligue 180.

### 2. Termo de consentimento

1. Na página **Atendimento**, leia o termo em voz alta.
2. Marque que a pessoa entendeu e concordou.
3. O nome é opcional: use um apelido se a pessoa preferir.
4. Abra o atendimento.

O termo vai impresso no pacote final, com espaço para as assinaturas.

### 3. Conectar o celular

- **Android pelo cabo:**
  1. Em **Dispositivos**, escolha a marca do celular e siga os passos para ligar a Depuração USB.
  2. Desbloqueie o celular e toque em "Permitir".
- **Android sem cabo** (Android 11 ou mais novo): use a depuração por Wi-Fi na mesma página. O celular e o
  computador precisam estar na mesma rede.
- **iPhone:**
  1. Desbloqueie o iPhone, toque em "Confiar" e use "Fazer backup e analisar".
  2. Se a pessoa já tem um backup no computador dela, informe a pasta.
  3. O backup criptografado traz mais dados; a senha não é guardada.

### 4. Varredura

- **Rápida** (1 a 2 minutos): para triagem.
- **Completa** (10 a 25 minutos): gera o bugreport e roda o MVT. Use quando houver suspeita forte
  ou indício de spyware mercenário.

Peça que a pessoa mantenha o celular desbloqueado e com a tela ligada.

### 5. Explicar o resultado

Use o **modo simples**: um semáforo, o que fazer agora e as áreas em linguagem do dia a dia.

- **Verde**: nenhum sinal foi encontrado. Isso **não prova** que o celular está limpo. Revise com a
  pessoa as **verificações manuais**: dispositivos conectados ao WhatsApp e à conta Google,
  compartilhamento de localização e desvio de chamadas.
- **Amarelo**: o celular está exposto (sistema desatualizado, Play Protect desligado, apps fora da
  loja). Ajude a pessoa a corrigir.
- **Vermelho**: há sinais de espionagem. **Não remova nada ainda.** Antes, combine com a pessoa:
  - onde ela vai ficar;
  - quem pode ajudar;
  - se quer registrar ocorrência ou pedir medida protetiva (Lei Maria da Penha, arts. 18 a 24).

  Só depois disso use "Remover…", que guarda uma cópia do app como evidência.

Para suspeita de spyware de governo ou de empresa de vigilância (jornalistas, ativistas,
defensores de direitos humanos), **não apague nada**. Encaminhe o pacote para a
[Access Now Helpline](https://www.accessnow.org/help/) ou para o
[Amnesty Security Lab](https://securitylab.amnesty.org/get-help/).

### 6. Entregar e encerrar

1. Em **Atendimento**, clique em **Baixar pacote (.zip)**. O pacote contém:
   - a pasta de evidências com a saída bruta de cada comando, o relatório e o `SHA256SUMS.txt`;
   - o **relatório para atendimento** de cada varredura (identificação, método, fatos, hashes,
     cadeia de custódia e base legal);
   - o termo de consentimento.
2. Copie o pacote para o pendrive da pessoa, ou imprima o relatório para atendimento (botão
   "Imprimir ou salvar em PDF").
3. Preencha a tabela de **cadeia de custódia** a cada entrega (CPP, arts. 158-A a 158-F).
4. Clique em **Encerrar e apagar**. As evidências desse atendimento saem do computador.
5. No celular:
   1. Desligue a Depuração USB e a por Wi-Fi.
   2. Toque em "Revogar autorizações de depuração USB".

## Checklist do atendimento

- [ ] Acolhimento e avaliação de risco imediato
- [ ] Termo lido e consentimento registrado
- [ ] Varredura concluída (rápida ou completa)
- [ ] Resultado explicado no modo simples e verificações manuais revisadas
- [ ] Plano de segurança combinado antes de qualquer remoção
- [ ] Pacote entregue (pendrive ou impresso) e cadeia de custódia preenchida
- [ ] Atendimento encerrado (dados apagados) e depuração desligada no celular
- [ ] Encaminhamento (Defensoria, DEAM, Ligue 180, Access Now), se for o caso

## Cuidados

- **Não** use o seu celular pessoal para fotografar telas do celular da pessoa.
- **Não** guarde cópias dos pacotes na instituição sem uma política de guarda de dados (LGPD:
  dados de violência são sensíveis).
- O relatório **não é laudo pericial**. Para processo criminal, a polícia ou o Ministério Público
  podem pedir perícia oficial. O pacote, com os hashes, ajuda nesse caminho.
- Atualize as bases toda semana (**Configurações › Atualizar bases**) para incluir os boletins de
  segurança mais recentes.

## Feedback do piloto

Depois de cada dia de atendimento, anote **sem nenhum dado pessoal**:

- quantos atendimentos foram feitos;
- quanto tempo levaram;
- em que passo as pessoas travaram;
- se houve achados vermelhos e para onde foram encaminhados.

Envie pelo formulário de [sugestão](https://github.com/bernardofernandezz/desgrampa/issues/new?template=ideia.yml)
ou pelo e-mail da instituição parceira.
