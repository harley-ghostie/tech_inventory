# Tech Inventory Scanner (Wappalyzer-like) — Single File Python

Automação de identificação de tecnologias por URL (similar ao Wappalyzer), gerando inventário **por categoria → tecnologia → versão → lista de URLs**.

Esse script foi pensado para uso em **plataforma de recon multi-client**, onde você precisa:
- varrer várias URLs;
- tolerar falhas (WAF, timeout, conexão recusada, DNS etc.);
- gerar saída pronta para alimentar frontend/API.

---

## ✅ O que ele faz

Para cada URL:
- Faz um `GET` HTTP/HTTPS
- Coleta:
  - headers
  - cookies
  - meta tags (`<meta name|property=... content=...>`)
  - HTML (body)
  - scripts (`<script src=...>`)
- Compara com fingerprints (assinaturas) do ecossistema Wappalyzer
- Calcula:
  - tecnologia detectada
  - versão (quando disponível via regex)
  - confiança (confidence)
  - categorias (via categories.json)

Depois:
- Gera inventário agrupado para visualização em “tabela” no frontend
- Se uma URL falhar, **não para o processo**: registra em `errors.json` e segue

---

## 📦 Requisitos

- Python 3.10+ (recomendado 3.12)
- `requests`

Instalação:

    pip install requests


##🧠 Fingerprints (obrigatório)

O script precisa de fingerprints de tecnologia:

categories.json (opcional, mas recomendado)

technologies (obrigatório):

ou technologies.json (arquivo único)

ou diretório com vários JSON: src/technologies/*.json

Opção recomendada (mirror público com estrutura quebrada em arquivos)

Exemplo (um mirror que costuma ter src/technologies/*.json e src/categories.json):

    git clone https://github.com/dochne/wappalyzer.git wappalyzer-fp


Estrutura esperada:

    wappalyzer-fp/
  src/
    categories.json
    technologies/
      a.json
      b.json
      ...


🚀 Uso rápido

##Crie urls.txt:

  https://example.com
  
  https://app.example.com
  
  https://portal.example.com

## Execute:

python3 tech_inventory_single.py \
  -i urls.txt \
  --technologies wappalyzer-fp/src/technologies \
  --categories wappalyzer-fp/src/categories.json \
  --confidence-min 50


🧾 Saídas geradas
per_url.json
Resultado por URL.

grouped_by_category.json
Resultado agrupado (pronto para tabela no frontend).

errors.json
URLs que falharam + motivo (ex: timeout, connection refused, DNS).

🔧 Parâmetros principais
Fingerprints

--technologies <path>
Caminho para technologies.json OU diretório src/technologies/.

--categories <path>
Caminho para categories.json (opcional, mas recomendado).

--fingerprints-dir <dir>
Pasta base (opcional). Ajuda o script a localizar arquivos automaticamente.

Controle de detecção

--confidence-min <int>
Filtra detecções com confiança menor que o valor informado (ex: 50).

Robustez / tolerância a falhas

--timeout <sec>
Timeout por URL.

--retries <n>
Número de tentativas em falha de request.

--backoff <sec>
Backoff base em segundos (multiplica por tentativa).

Controle de ritmo (para reduzir bloqueio por volume)

--rate-limit <sec>
Sleep fixo entre URLs.

--jitter <sec>
Adiciona aleatoriedade ao sleep: rate-limit + rand(0..jitter).

User-Agent

--user-agent "..."
Define um UA fixo. Default: ReconTechInventory/1.0

--random-ua
Escolhe um UA aleatório por request (pool interno no script).

Cookies (para endpoints que exigem sessão)

--cookie "session=...; token=..."
Envia header Cookie: em todas as requisições.

Arquivos de saída

--out-per-url per_url.json

--out-grouped grouped_by_category.json

--out-errors errors.json

🧪 Exemplo “modo mais stealth” (menos ruído)

    python3 tech_inventory_single.py \
  -i urls.txt \
  --technologies wappalyzer-fp/src/technologies \
  --categories wappalyzer-fp/src/categories.json \
  --confidence-min 50 \
  --random-ua \
  --rate-limit 0.3 \
  --jitter 0.4 \
  --retries 1 \
  --backoff 1.0

📊 Formato do grouped_by_category.json

Exemplo:

  [
  {
    "category": "CMS",
    "items": [
      {
        "technology": "WordPress",
        "version": "5.2.3",
        "count": 2,
        "urls": [
          "https://www.demo.com.br",
          "https://www.demo2.com.br"
        ]
      }
    ]
  }
]

Isso é ideal para o frontend renderizar:

seção = categoria

linhas = tecnologia + versão + ambientes

🧩 Integração na plataforma (multi-client)

Fluxo sugerido:

Buscar URLs do cliente no banco

Rodar o script (ou chamar função interna) para gerar grouped_by_category.json

Persistir JSON em tabela client_tech_inventory (jsonb)

Frontend consulta por client_id e exibe a “caixa” com os grupos

Estratégia recomendada: cache por TTL (ex: 24h) e re-scan incremental.

⚠️ Limitações conhecidas

Detecção é baseada em HTTP. Sem browser emulação, alguns frameworks SPA podem ter detecção inferior.

Alguns ambientes bloqueiam request simples (WAF, ACL, allowlist).

Versões nem sempre são detectáveis; nesse caso o script usa unknown.

📌 Troubleshooting
“404: Not Found” no technologies.json/categories.json

Você baixou o arquivo do lugar errado (mudança de estrutura do repositório). Use mirror com src/technologies/*.json e aponte --technologies para o diretório.

“Connection refused / timeout”

O script vai registrar em errors.json e continuar. Ajuste:

--timeout

--retries

--rate-limit/--jitter

✅ Checklist para commit

 Script funcionando com um conjunto mínimo de URLs

 Fingerprints versionados internamente (ideal) ou documentados

 errors.json gerado corretamente em falhas

 Saída grouped_by_category.json validada para frontend

makefile

  ::contentReference[oaicite:0]{index=0}



