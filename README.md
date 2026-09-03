# Security Headers Scanner

Cole a URL de um site e receba uma nota de **A a F** pelos headers de segurança que ele envia — com o risco real de cada header ausente e o valor exato para corrigir.

```
github.com     B   89/100
mozilla.org    C   71/100
example.com    F    9/100
localhost      →   bloqueado: endereço interno
```

---

## O problema técnico interessante

O browser **não consegue** ler os headers de resposta de um terceiro: CORS impede. Então o scanner precisa de um backend que faça o pedido.

E é aí que ele vira um problema de segurança: um serviço que faz requisições HTTP para um hostname escolhido por um usuário anônimo é a definição de **SSRF (Server-Side Request Forgery)**. Sem cuidado, `http://169.254.169.254/latest/meta-data/` transforma este app num proxy para credenciais de nuvem, e `http://127.0.0.1:6379/` num proxy para o Redis da máquina.

A defesa está em [`backend/app/url_guard.py`](backend/app/url_guard.py), em quatro camadas:

| Camada | O que faz | Ataque que fecha |
|---|---|---|
| **Estrutural** | Só `http`/`https`, só portas 80/443, sem credenciais na URL | `file:///etc/passwd`, `https://confiavel.com@127.0.0.1/`, varredura de portas internas |
| **Endereço** | Todo IP resolvido precisa ser público e roteável — incluindo IPv4 embutido em IPv6 | `169.254.169.254`, `10.0.0.5`, `::ffff:127.0.0.1`, `64:ff9b::7f00:1` |
| **Pinning** | Conecta no **IP que foi validado**, com o hostname só no `Host` e no SNI | DNS rebinding: o nome resolve para um IP público na checagem e para `127.0.0.1` no socket |
| **Redirects** | Segue redirects manualmente, revalidando cada salto do zero | Host público que responde `302 Location: http://localhost/` |

Detalhe que quase todo tutorial de SSRF erra: se o DNS devolve vários endereços, **um único interno reprova o host inteiro**. Filtrar só os "bons" deixa um round-robin a uma moeda de distância de alcançar a rede interna.

O corpo da resposta nunca é lido — só os headers chegam, e a conexão fecha. Um alvo hostil não consegue fazer o scanner baixar 4 GB.

## Como a nota é calculada

Cada check devolve uma fração de 0 a 1 do seu peso. Os pesos somam 100, e [um teste falha se pararem de somar](frontend/src/analysis/__tests__/analyze.test.ts) — sem isso, adicionar um check mudaria silenciosamente o significado de toda nota já emitida.

| Header | Peso | Por que esse peso |
|---|---:|---|
| `Content-Security-Policy` | 30 | Última barreira contra XSS |
| `Strict-Transport-Security` | 20 | Sem ele, a primeira visita é interceptável (sslstrip) |
| `X-Frame-Options` / `frame-ancestors` | 15 | Clickjacking |
| `X-Content-Type-Options` | 10 | MIME sniffing vira XSS armazenado a partir de upload |
| `Referrer-Policy` | 10 | Vazamento de token de reset em query string |
| `Permissions-Policy` | 10 | Reduz o estrago de um script de terceiro comprometido |
| Exposição da stack | 5 | `nginx/1.18.0` encurta o trabalho de quem procura um CVE |

`A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · E ≥ 50 · F < 50`

A pontuação é graduada, não binária. Alguns exemplos do que isso significa:

- CSP com `'unsafe-inline'` **e** um nonce não é penalizada — o browser ignora `'unsafe-inline'` quando há nonce.
- Faltar `base-uri` é penalizado mesmo com `default-src 'self'`, porque `base-uri` **não** tem fallback para `default-src`. Uma tag `<base>` injetada reescreve todas as URLs relativas da página.
- Dois headers `Content-Security-Policy` são **interseccionados** pelo browser, então a nota segue a política mais restritiva.
- `Referrer-Policy` ausente é **aviso, não falha**: navegadores atuais já usam `strict-origin-when-cross-origin` por padrão.
- Um site em HTTP puro tem a nota **limitada a 45**, por melhores que sejam os headers: todos eles são conselhos quando a conexão pode ser reescrita em trânsito.

## Arquitetura

```
frontend/  React 19 + TS strict + React Query   → faz a análise e a nota
backend/   FastAPI + httpx                      → só busca os headers, com blindagem
```

A nota mora no frontend de propósito. O backend fica com uma responsabilidade só (buscar headers em segurança), e as regras de pontuação ficam em funções puras, testáveis ao lado da UI que as explica — sem rede, sem browser, sem mock server.

**Tipagem.** `tsconfig` roda com `strict`, `noUncheckedIndexedAccess` e `exactOptionalPropertyTypes`. Zero `any`. O estado do scan é uma união discriminada:

```ts
type ScanState =
  | { status: 'idle' }
  | { status: 'scanning'; url: string }
  | { status: 'success'; report: ScanReport }
  | { status: 'error'; url: string; failure: ScanFailure };
```

Um `switch` sobre ela em [`App.tsx`](frontend/src/App.tsx) é exaustivo: adicionar um estado quebra a compilação até que alguém o renderize. O hook [`useScan`](frontend/src/hooks/useScan.ts) reduz os flags ortogonais do React Query (`isPending`, `isFetching`, `isError`, `data`, `error`) a essa união — assim é impossível renderizar um spinner ao lado de um relatório velho.

**Cache.** A análise roda no `select` do React Query, que a memoiza. Reanalisar a mesma URL sai do cache sem tocar na rede.

## Acessibilidade

Não é enfeite; é o que separa um projeto pessoal de um entregável:

- O status de cada check é **ícone + palavra**, nunca só cor (WCAG 1.4.1).
- O foco vai para o cabeçalho do relatório quando ele chega — sem isso, quem usa teclado ou leitor de tela fica parado no botão sem saber que a página mudou.
- Resultados vivem numa região `aria-live="polite"` com `aria-busy` durante o scan.
- Os cards usam `<details>`/`<summary>`: operação por teclado, estado e busca na página vêm do browser, de graça.
- Erros de formulário ligados ao input por `aria-describedby` + `aria-invalid`.
- `prefers-reduced-motion` respeitado; foco visível nunca removido; skip link.

## Testes

```
104 testes  ·  84 na lógica de análise, 20 em componentes
```

- **Análise** (Vitest): parsing de CSP/HSTS/Permissions-Policy, cada check isoladamente, e as invariantes da nota.
- **Componentes** (Vitest + Testing Library): validação do formulário, o fluxo completo com `fetch` mockado, cache, cada tela de erro, e as asserções de acessibilidade.
- **Backend** (pytest): 57 testes, com a bateria de bypasses de SSRF — metadata endpoint, IPv4-mapped IPv6, NAT64, 6to4, `usuario@host`, portas internas.

> **Por que Vitest e não Jest:** API idêntica (`describe`/`it`/`expect`) e mesmo Testing Library, mas nativo do Vite — sem uma segunda pipeline de build só para os testes. Migrar para o Jest seria trocar de runner, não reescrever testes.

## Rodando

**Docker (tudo de uma vez):**

```bash
docker compose up --build
# http://localhost:8080
```

**Local:**

```bash
# terminal 1
cd backend
python -m venv .venv && ./.venv/bin/pip install -r requirements-dev.txt
./.venv/bin/uvicorn app.main:app --reload --port 8000

# terminal 2
cd frontend
npm install && npm run dev      # http://localhost:5173, /api já vai por proxy
```

**Testes:**

```bash
cd backend  && ./.venv/bin/python -m pytest      # 57 testes
cd frontend && npm test                          # 104 testes
cd frontend && npm run typecheck                 # tsc --noEmit, zero erros
```

## Configuração

Tudo por variável de ambiente, com defaults seguros ([`backend/app/config.py`](backend/app/config.py)):

| Variável | Default | |
|---|---|---|
| `RATE_LIMIT_REQUESTS` | `10` | scans por janela, por cliente |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | tamanho da janela |
| `MAX_CONCURRENT_SCANS` | `8` | teto de scans simultâneos no processo |
| `TRUST_PROXY_HEADERS` | `false` | só ative atrás de um proxy que reescreve `X-Forwarded-For` |
| `SCAN_TOTAL_TIMEOUT` | `10` | teto do scan inteiro, em segundos |
| `CORS_ORIGINS` | `http://localhost:5173` | lista separada por vírgula |

`TRUST_PROXY_HEADERS` fica `false` por padrão porque `X-Forwarded-For` é controlado pelo cliente: confiar nele sem um proxy na frente dá a qualquer um infinitas identidades para burlar o rate limit.

## Limitações conhecidas

São escolhas, não descuidos:

- **Rate limiting é em memória.** Correto para um processo, que é o que o Compose sobe. Com múltiplos workers precisaria de Redis (`INCR` + `EXPIRE`); a interface em [`rate_limit.py`](backend/app/rate_limit.py) é o que seria trocado.
- **A preload list do HSTS não é consultada.** Um domínio nela está protegido mesmo sem o header, e isso não aparece na resposta HTTP. O relatório diz isso em vez de fingir que sabe.
- **Só a resposta de uma URL é analisada.** Headers costumam variar por rota; `/` não representa o site inteiro.
- **Cookies não são avaliados.** `Secure`, `HttpOnly` e `SameSite` mereceriam um check próprio — é a próxima coisa que eu adicionaria.
