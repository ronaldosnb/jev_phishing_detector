# jev-phishing-detector

Monitora caixas de entrada do Gmail / Google Workspace e do Outlook.com / Microsoft 365,
analisa cada email novo com o [Jev](https://openrouter.ai/docs/guides/community/jev)
(modelo de decisao System One da TypeSafe) e, quando o email e suspeito, aplica a etiqueta
de aviso e o retira da caixa de entrada.

## Como funciona

1. A cada `POLL_INTERVAL_SECONDS` o servico busca os emails novos da caixa de entrada.
2. Se o remetente esta na lista de confiaveis **e** o provedor confirmou a autenticidade
   do dominio (DMARC aprovado), o email e liberado sem chamar o Jev.
3. Os demais sao enviados ao Jev em uma unica requisicao com perguntas tipadas
   (`phishing`, `pede_urgencia`, `falsa_identidade`, `categoria`).
4. Se a probabilidade de phishing for `>= PHISHING_THRESHOLD`:
   - **Gmail**: adiciona a etiqueta `Suspeita de Phishing` e remove da Caixa de entrada.
   - **Microsoft**: adiciona a categoria `Suspeita de Phishing` e move para a pasta de mesmo nome.

Nada e apagado: o email continua disponivel na etiqueta/pasta para revisao.
Se o Jev ou o provedor falhar, o email fica intocado e e reprocessado no ciclo seguinte.

Um remetente confiavel cujo email **nao** passa na autenticacao e analisado normalmente.
Sem isso, bastaria forjar o `From` de um colega para escapar da analise.

## Instalacao

```bash
uv sync
cp .env.example .env   # preencha JEV_API_KEY
```

### Jev

Coloque a chave em `JEV_API_KEY`. Para usar via OpenRouter, ajuste:

```
JEV_BASE_URL=https://openrouter.ai/api/v1
JEV_MODEL=typesafe/jev-1.13
```

### Google

1. No Google Cloud Console, crie/escolha um projeto e ative a **Gmail API**.
2. Configure a tela de consentimento OAuth (External para @gmail.com, Internal para Workspace)
   com o escopo `https://www.googleapis.com/auth/gmail.modify` e adicione seu endereco em *Test users*.
3. Crie uma credencial **OAuth client ID** do tipo **Desktop app**, baixe o JSON e aponte
   `GOOGLE_CLIENT_SECRETS` para ele.
4. `uv run jev-phishing auth google`

Com o app em modo *Testing* o Google expira o acesso a cada 7 dias; publique o app
(*In production*) para evitar reautorizar toda semana.

### Microsoft

1. Em entra.microsoft.com > App registrations > New registration.
2. Tipos de conta: *Accounts in any organizational directory and personal Microsoft accounts*
   (mantenha `MS_TENANT=common`). Sem redirect URI.
3. Authentication > **Allow public client flows: Yes**.
4. API permissions > Microsoft Graph > Delegated: `Mail.ReadWrite` e `User.Read`
   (tenants corporativos podem exigir consentimento do administrador).
5. Copie o *Application (client) ID* para `MS_CLIENT_ID`.
6. `uv run jev-phishing auth microsoft` e siga o codigo exibido.

## Uso

```bash
# Lista de confiaveis (dominio cobre tambem os subdominios)
uv run jev-phishing trust add empresa.com --note "colegas"
uv run jev-phishing trust add fornecedor@parceiro.com.br
uv run jev-phishing trust list
uv run jev-phishing trust remove empresa.com

# Ver o que seria feito, sem alterar nenhum email
uv run jev-phishing run --once --dry-run

# Servico continuo
uv run jev-phishing run

uv run jev-phishing status
```

Na primeira execucao sao analisados os emails da ultima hora.

## Desenvolvimento

```bash
uv run pytest
```

Os tokens OAuth e o banco SQLite ficam em `DATA_DIR` (padrao `./data`, fora do git).
