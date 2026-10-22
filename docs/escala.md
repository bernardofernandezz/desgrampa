# Como levar o Desgrampa a todo o Brasil

Plano de escala para um projeto mantido por uma pessoa. O código cobre as fases 0 a 5 do
[ROADMAP](ROADMAP.md); o que segue depende de pessoas e instituições.

## 1. Testar com quem não é de TI (antes do piloto)

Protocolo de 1 hora, com 3 a 5 pessoas sem formação técnica (de preferência quem atende vítimas):

1. Entregue um celular Android de teste e o computador com o Desgrampa recém-instalado, sem instruções.
2. Peça: "Descubra se este celular está sendo espionado". Observe sem ajudar e anote onde a pessoa travou.
3. Depois, mostre o resultado de um celular "infectado" (aparelho de laboratório) e pergunte:
   - "O que você faria agora?"
   - "O que significa o amarelo?"
   - "Onde você pediria ajuda?"
4. Meça:
   - tempo até a primeira varredura;
   - quantas pessoas ativaram a depuração USB sozinhas;
   - quantas entenderam o semáforo;
   - quantas encontraram o "Sair rápido" e a página de ajuda.

Meta para o piloto: 4 de 5 pessoas concluem a varredura sozinhas e explicam o resultado com as
próprias palavras.

## 2. Piloto com 1 ou 2 instituições

Candidatos naturais:

- núcleos de prática jurídica de universidades públicas;
- Defensorias Públicas que já têm núcleo de defesa da mulher (NUDEM);
- ONGs de direitos digitais que fazem clínicas de segurança.

O que levar: o guia [atendimento.md](atendimento.md), um computador configurado com
`desgrampa --atendimento`, cabos e pendrives.

Mensagem de contato (modelo):

> Olá! Sou desenvolvedor do Desgrampa, uma ferramenta gratuita e de código aberto que verifica se um
> celular Android ou iPhone tem aplicativo espião, foi invadido ou está vulnerável. Ela roda num
> computador, sem enviar dados para fora, e gera um relatório para atendimento com hashes, cadeia de
> custódia e base legal (CP 147-A, 154-A; Lei Maria da Penha, art. 7º, II). Gostaríamos de fazer um
> piloto de 4 semanas com a equipe de vocês: treinamos em 1 hora, deixamos um computador configurado
> e recolhemos só dados anônimos de uso (quantos atendimentos, tempo, dificuldades). Podemos conversar?

## 3. Confiança: auditoria e builds verificáveis

- **Auditoria externa gratuita:** pedir pelo
  - [Open Technology Fund — Red Team Lab](https://www.opentech.fund/labs/red-team-lab/);
  - [OSTIF](https://ostif.org/).

  Levar o [modelo de ameaça](modelo-de-ameaca.md) e o escopo de SECURITY.md.
- **Proveniência:** cada release já sai com atestação Sigstore (`gh attestation verify`).
- **Assinatura de código no Windows:** pedir a assinatura gratuita da
  [SignPath Foundation](https://signpath.org/), para o SmartScreen parar de bloquear o executável.

## 4. Divulgação

- Site com download e tutoriais: `site/`, publicado pelo workflow `pages.yml` (GitHub Pages).
- Vídeos curtos (até 1 minuto cada):
  - ligar a depuração USB em Samsung, Motorola e Xiaomi;
  - o que significa cada cor do semáforo;
  - como usar o "Sair rápido".
- Parcerias de divulgação:
  - Coding Rights;
  - InternetLab;
  - SaferNet;
  - Instituto Igarapé;
  - Data Privacy Brasil;
  - Coalizão contra o Stalkerware (o Desgrampa pode entrar como membro técnico).

## 5. Financiamento para sair do "dev solo"

- [Open Technology Fund — Internet Freedom Fund](https://www.opentech.fund/funds/internet-freedom-fund/)
- [Digital Defenders Partnership](https://www.digitaldefenders.org/)
- [NLnet — NGI Zero](https://nlnet.nl/) (projetos abertos de privacidade)
- Editais nacionais de inovação social e de enfrentamento à violência contra a mulher (ministérios,
  fundações estaduais de amparo à pesquisa)

Com financiamento, priorizar:

1. uma pessoa de UX/acessibilidade;
2. uma pessoa para os indicadores brasileiros e o contato com a AssoEchap;
3. auditoria;
4. a assinatura de código.

## 6. Métricas (sem telemetria)

O Desgrampa não coleta dados. Para saber se está funcionando:

- downloads por release (GitHub);
- issues e indicadores recebidos;
- relatórios voluntários dos pontos de atendimento (só números, nada pessoal).
