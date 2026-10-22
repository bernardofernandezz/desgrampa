# Indicadores brasileiros

`desgrampa/dados/br-indicators.yaml` complementa a base da
[AssoEchap](https://github.com/AssoEchap/stalkerware-indicators) com o contexto brasileiro.

## O que o arquivo faz

1. **Marca as famílias vendidas no Brasil.** Quando um app desses aparece, o achado informa os sites
   de venda e lembra que vender ou distribuir programa para invadir aparelhos também é crime
   (Código Penal, art. 154-A, § 1º). Isso ajuda a delegacia a chegar a quem vende.
2. **Recebe indicadores novos** encontrados no Brasil antes de eles entrarem na AssoEchap. Quando um
   indicador repete um que já está na AssoEchap, ele continua atribuído a ela.

## Formato

É o mesmo `ioc.yaml` da AssoEchap, com dois campos a mais:

```yaml
- name: NomeComercial
  packages: [br.com.exemplo.espiao]
  certificates: [AABBCC...]          # SHA-1 do certificado de assinatura do APK
  websites: [exemplo.com.br]         # sites de venda
  c2:
    domains: [api.exemplo.com.br]
    ips: [203.0.113.10]
  vendido_no_brasil: true
  fonte: "link para a análise, amostra pública ou página do vendedor"
```

## Como contribuir

1. Abra uma issue com o modelo **"Novo indicador"**. Não anexe dados de vítimas.
2. Todo indicador precisa de **fonte verificável**: análise publicada, hash de amostra disponível a
   pesquisadores ou página do próprio vendedor.
3. Envie também para a AssoEchap (https://github.com/AssoEchap/stalkerware-indicators/issues), para
   que o indicador sirva a todas as ferramentas, inclusive o MVT e o TinyCheck.
4. Rode `python -m unittest tests.test_br` antes do PR: o teste confere que o arquivo carrega e que
   toda entrada tem `fonte`.

## Por que não inventar indicadores

Um falso positivo de stalkerware pode destruir uma relação de confiança ou levar alguém a agir com
base num erro. Um falso negativo deixa a vítima exposta. Por isso o arquivo começa com as famílias
brasileiras já documentadas pela AssoEchap e só cresce com fonte.
