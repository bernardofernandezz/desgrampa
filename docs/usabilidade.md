# Kit do teste de usabilidade

Um teste com 3 a 5 pessoas sem formação técnica, de preferência quem atende vítimas: atendentes de
CRAM, estagiárias(os) de Defensoria e voluntárias(os) de ONG. Dura cerca de 1 hora por pessoa.

## Preparação

- Computador com o Desgrampa recém-instalado pelo executável da release, sem bases baixadas, para
  testar também a primeira execução.
- **Celular A** (Android de laboratório, limpo), com a Depuração USB **desligada**.
- **Celular B** (Android de laboratório "infectado"), com um app de monitoramento comercial instalado
  pela loja, como Life360, e um proxy configurado no Wi-Fi. **Nunca use o celular de uma vítima real.**
- Um cabo de dados e um cronômetro.
- Este roteiro impresso, para quem facilita.

## Termo (ler para a pessoa)

> Estamos testando o programa, não você. Não existe resposta errada. Vou observar e anotar, sem
> gravar seu rosto ou sua voz. Você pode parar quando quiser. Nenhum dado seu será coletado.

## Tarefas

Peça uma de cada vez, sem dar dicas. Só ajude se a pessoa ficar travada por mais de 3 minutos, e
anote que precisou de ajuda.

| # | Tarefa (como falar) | Sucesso quando |
|---|---|---|
| 1 | "Abra o programa e conecte o celular A." | O painel mostra o aparelho como "Conectado" |
| 2 | "Descubra se este celular está sendo espionado." | Varredura concluída e a pessoa lê o resultado |
| 3 | "Agora faça o mesmo com o celular B." | Varredura do celular B concluída |
| 4 | "O que esse resultado significa? O que você faria agora?" | Cita o semáforo e pelo menos um passo de "O que fazer agora" |
| 5 | "Alguém entrou na sala e você não quer que veja a tela. O que faz?" | Usa "Sair rápido" ou Esc duas vezes |
| 6 | "Onde você encontraria o telefone da Defensoria do seu estado?" | Chega à página "Preciso de ajuda" e escolhe o estado |
| 7 | "Guarde um relatório para levar a uma delegacia." | Baixa "Para atendimento ou autoridade" ou o pacote .zip |
| 8 | "Desfaça o que você ligou no celular." | Desliga a Depuração USB |

## Anotar por tarefa

- tempo;
- se concluiu, se precisou de ajuda ou se desistiu;
- onde clicou primeiro;
- frases da pessoa ("não sei o que é depuração", "isso é grave?").

## Perguntas finais (escala de 1 a 5)

1. Foi fácil conectar o celular?
2. Você entendeu o resultado?
3. Você confiaria nesse resultado para tomar uma decisão?
4. Você indicaria para alguém que atende vítimas?
5. O que mais confundiu você? (aberta)

## Critério para seguir ao piloto

- 4 de 5 pessoas concluem as tarefas 1 a 4 sem ajuda.
- Todas encontram o "Sair rápido" (tarefa 5) em menos de 30 segundos.
- Média de 4 ou mais na pergunta 2.

Se algum critério falhar, abra uma issue com a tarefa, o que aconteceu e a frase da pessoa (sem nome),
e corrija antes do piloto.

## Planilha de resultados

| Pessoa (P1…P5) | T1 | T2 | T3 | T4 | T5 | T6 | T7 | T8 | Q1 | Q2 | Q3 | Q4 | Observações |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | | | | | | | | | | | | | |
