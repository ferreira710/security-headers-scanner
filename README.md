# Security Headers Scanner

[![CI](https://github.com/ferreira710/security-headers-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/ferreira710/security-headers-scanner/actions/workflows/ci.yml)

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

A defesa está em [`backend/internal/scanner/guard.go`](backend/internal/scanner/guard.go), em quatro camadas:

| Camada | O que faz | Ataque que fecha |
|---|---|---|
| **Estrutural** | Só `http`/`https`, só portas 80/443, sem credenciais na URL | `file:///etc/passwd`, `https://confiavel.com@127.0.0.1/`, varredura de portas internas |
| **Endereço** | Todo IP resolvido precisa ser público e roteável — incluindo IPv4 embutido em IPv6 | `169.254.169.254`, `10.0.0.5`, `::ffff:127.0.0.1`, `64:ff9b::7f00:1` |
| **Pinning** | Conecta no **IP que foi validado**, com o hostname só no `Host` e no SNI. O hook `Control` do `net.Dialer` confere de novo o endereço que o kernel vai usar, depois do DNS e antes do `connect()` | DNS rebinding: o nome resolve para um IP público na checagem e para `127.0.0.1` no socket |
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
backend/   Go, stdlib (+ x/net/idna)            → só busca os headers, com blindagem
```

O backend tem uma implementação e duas portas de entrada, o que evita a situação em que produção roda um código e os testes cobrem outro:

```
backend/internal/scanner/   guard + fetch: o SSRF e a requisição de saída
backend/internal/api/       o handler HTTP, rate limit e CORS
backend/cmd/server/         binário do container — Docker e self-host
backend/netlify/functions/  adaptador Lambda; monta o mesmo handler
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
115 testes  ·  95 na lógica de análise, 20 em componentes
```

- **Análise** (Vitest): parsing de CSP/HSTS/Permissions-Policy, cada check isoladamente, e as invariantes da nota.
- **Componentes** (Vitest + Testing Library): validação do formulário, o fluxo completo com `fetch` mockado, cache, cada tela de erro, e as asserções de acessibilidade.
- **Backend** (`go test`): 50 testes e subtestes, vários table-driven, com a bateria de bypasses de SSRF — metadata endpoint, IPv4-mapped IPv6, NAT64, 6to4, `usuario@host`, portas internas — mais a regra do round-robin: um único endereço interno reprova o host inteiro.

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
go run ./backend/cmd/server     # :8000

# terminal 2
cd frontend
npm install && npm run dev      # http://localhost:5173, /api já vai por proxy
```

Ou, para exercitar o caminho de produção inteiro — site estático, redirect e function Go:

```bash
npm --prefix frontend run build && netlify dev
```

**Testes:**

```bash
go test ./...                                    # 50 testes
cd frontend && npm test                          # 115 testes
cd frontend && npm run typecheck                 # tsc --noEmit, zero erros
```

## Configuração

Tudo por variável de ambiente, com defaults seguros ([`backend/internal/config/config.go`](backend/internal/config/config.go)):

| Variável | Default | |
|---|---|---|
| `RATE_LIMIT_REQUESTS` | `10` | scans por janela, por cliente |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | tamanho da janela |
| `MAX_CONCURRENT_SCANS` | `8` | teto de scans simultâneos no processo |
| `TRUST_PROXY_HEADERS` | `false` | só ative atrás de um proxy que reescreve `X-Forwarded-For` |
| `SCAN_TOTAL_TIMEOUT` | `10` | teto do scan inteiro, em segundos |
| `CORS_ORIGINS` | `http://localhost:5173` | lista separada por vírgula |

`TRUST_PROXY_HEADERS` fica `false` por padrão porque `X-Forwarded-For` é controlado pelo cliente: confiar nele sem um proxy na frente dá a qualquer um infinitas identidades para burlar o rate limit.

## Deploy

As duas metades ficam na Netlify: o frontend como estático, a API como function Go sob `/api`. Tudo está em [`netlify.toml`](netlify.toml) — apontar a Netlify para o repositório basta, sem variável de ambiente para configurar.

Manter a API no mesmo origin não é estética: é o que permite ao CSP do site dizer `connect-src 'self'`, e faz o app ser same-origin em dev (proxy do Vite), no Docker (nginx) e em produção, sem preflight de CORS em lugar nenhum.

Dois detalhes que a function trata sozinha, em [`backend/netlify/functions/scan/main.go`](backend/netlify/functions/scan/main.go):

- **O teto do scan cai para 8s.** O orçamento síncrono de uma function é de 10s; se o nosso timeout fosse igual, um alvo lento mataria a invocação antes de conseguirmos responder com o erro tipado, e o usuário veria a página de erro da Netlify em vez de "o alvo demorou demais".
- **`TRUST_PROXY_HEADERS` liga sozinho.** Ali sempre há a borda da Netlify na frente, e é ela quem define `x-nf-client-connection-ip` — o header não vem do cliente, que é a condição para o rate limiter confiar num IP encaminhado.

E um terceiro, na borda: o redirect `/api/*` carrega uma regra `[redirects.rate_limit]` de 20 req/60s por IP. Ela existe porque um contador em memória se multiplica pelo número de instâncias quentes, e um burst é exatamente o que cria instâncias. O teto da borda é deliberadamente mais alto que os 10/60s da aplicação: assim quem estoura o limite normal recebe a nossa resposta tipada, com `Retry-After`, e não o 429 cru da Netlify — que o frontend não saberia ler.

O container continua sendo o caminho de self-host, e a imagem final é um `FROM scratch` de ~10 MB: binário estático, sem shell, sem gerenciador de pacotes, UID não-privilegiado.

## Limitações conhecidas

São escolhas, não descuidos:

- **O rate limiting tem duas camadas, de propósito.** O limiter em [`ratelimit.go`](backend/internal/api/ratelimit.go) é em memória: correto para um processo, mas em serverless vira um teto *por instância*, e duas instâncias quentes dobram o limite efetivo. Por isso ele é o mais baixo dos dois (10/60s) e responde primeiro, com JSON tipado que a UI sabe exibir; o teto real é a regra de rate limit presa ao redirect `/api/*` no [`netlify.toml`](netlify.toml), contada na borda antes de a function rodar. Num deploy com múltiplos workers e sem borda, a saída seria Redis (`INCR` + `EXPIRE`) atrás da mesma interface.
- **A ordem dos headers na resposta é por nome, não a da rede.** O `net/http` entrega os headers num mapa, então a ordem de chegada entre nomes diferentes não é recuperável; repetições do *mesmo* nome preservam a ordem, que é o que a análise precisa para interseccionar duas CSPs. Headers hop-by-hop (`Connection`, `Transfer-Encoding`) não aparecem — o `net/http` os consome, e nenhum deles entra na nota.
- **A preload list do HSTS não é consultada.** Um domínio nela está protegido mesmo sem o header, e isso não aparece na resposta HTTP. O relatório diz isso em vez de fingir que sabe.
- **Só a resposta de uma URL é analisada.** Headers costumam variar por rota; `/` não representa o site inteiro.
- **Cookies não são avaliados.** `Secure`, `HttpOnly` e `SameSite` mereceriam um check próprio — é a próxima coisa que eu adicionaria.

## Licença

MIT — veja [LICENSE](LICENSE).
