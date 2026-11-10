# VulnForge Lab: Web Scanner Benchmark Platformu, Mimari ve Uygulama Planı

> **UYARI:** Bu proje kasıtlı olarak zafiyetli bir uygulamadır. Yalnızca izole yerel ortamda (VM / ayrı Docker ağı) çalıştırılmalı, asla internete açılmamalıdır. Tüm portlar varsayılan olarak `127.0.0.1`'e bağlanır.

---

## 1. Amaç ve Kapsam

### 1.1 Amaç
Geliştirilen web tarayıcı (DAST / crawler / API scanner) uygulamasının **etkinliğini ölçülebilir** şekilde test etmek:

- Tespit oranı (recall), yanlış pozitif oranı (precision), kapsama (crawl coverage)
- Zafiyet sınıfı bazında ve zorluk seviyesi bazında başarı
- Tarama süresi, istek sayısı, kaynak tüketimi

### 1.2 Önemli gerçekçilik notu
"Bugüne kadar bilinen tüm zafiyetler" tek bir uygulamada teknik olarak mümkün değildir (binlerce CWE, binlerce CVE). Bu projenin hedefi:

- **OWASP Top 10 (2021)**, **OWASP API Security Top 10 (2023)**, **OWASP ASVS** ve **CWE Top 25** kapsamının **tamamı**
- Bunun yanında SANS/CWE'de sık görülen, scanner'ların kaçırdığı **ileri seviye sınıflar** (request smuggling, cache poisoning, race condition, business logic, OAuth/SAML/JWT, WebSocket, GraphQL, deserialization vb.)
- Her sınıf için **birden fazla varyant** (bağlam, encoding, filtre, zorluk)
- Ölçüm için **ground truth** + **kontrol (güvenli) endpoint'ler**

### 1.3 Mevcut projelerden farklar (DVWA, Juice Shop, bWAPP, WebGoat, crAPI, VAmPI)

| Özellik | Mevcut projeler | VulnForge Lab |
|---|---|---|
| Ground truth (makine okunur) | Yok / kısmi | `vulns.json` + otomatik skor |
| Zorluk seviyeleri | DVWA'da 3 seviye | Her zafiyet için 5 seviye (L0 güvenli kontrol → L4 WAF bypass) |
| Güvenli kontrol endpoint'leri (FP ölçümü) | Yok | Her zafiyetin güvenli ikizi |
| Çok dilli / çok teknolojili | Genelde tek | PHP, Node, Python, Java, Go, .NET (opsiyonel), Ruby (opsiyonel) |
| Blind zafiyetler için OOB (out-of-band) doğrulama | Yok | Dahili OOB collector (DNS + HTTP) |
| Crawl zorlukları (SPA, WebSocket, çok adımlı akış) | Sınırlı | Ayrı "crawl-lab" servisi |
| Reset / deterministik durum | Manuel | `POST /__lab/reset`, seed'li ve tekrarlanabilir |
| WAF / rate-limit / bot koruması katmanı | Yok | Opsiyonel ModSecurity + rate limiter profilleri |
| Altyapı zafiyetleri (zayıf TLS, açık servisler) | Yok | Nginx TLS profilleri, açık Redis/ES/MinIO vb. |
| SCA (eski kütüphane) testi | Kısmi | Bilinçli eski sürüm manifestleri + bilinen CVE listesi |
| Zafiyet modları (toggle) | Yok | Env ile zafiyet açma/kapama, profil bazlı |
| Skor raporu (precision/recall/F1, HTML) | Yok | `scorer` CLI + HTML rapor |

---

## 2. Tasarım İlkeleri

1. **Ground truth birinci sınıf vatandaş:** Her zafiyet kodda bir dekoratör/etiketle işaretlenir; `vulns.json` buradan **otomatik üretilir** (elle yazılmaz, sapma olmaz).
2. **Güvenli ikiz (control) kuralı:** Her zafiyetli endpoint için aynı arayüze sahip, doğru güvenli uygulanmış bir endpoint bulunur. Bunlar FP ölçer.
3. **Seviye sistemi:** L0 (güvenli) / L1 (filtresiz) / L2 (basit filtre) / L3 (güçlü filtre, encoding/bypass) / L4 (WAF arkasında veya bağlam gerektiren).
4. **Deterministik:** Tohumlu (seed) veri, tek komutla sıfırlama, sabit kimlikler.
5. **Gözlemlenebilirlik:** Her istek, tetiklenen zafiyet ve "sömürü başarılı" olayı loglanır. Scanner'ın gerçekten sömürü kanıtı üretip üretmediği ölçülebilir.
6. **Modülerlik:** Her servis bağımsız konteyner; `docker compose --profile ...` ile alt küme çalıştırılabilir.
7. **Izolasyon:** Yalnızca loopback; konteyner `cap_drop`, `read_only` (mümkün olduğunda), kaynak limitleri; tehlikeli sınıflar (RCE) sandbox içinde.
8. **Tek komutla çalışma:** `docker compose up -d` ile hepsi ayağa kalkar; sağlık kontrolleri (`healthcheck`) ile hazır olma beklenir.

---

## 3. Üst Seviye Mimari

```
                        ┌─────────────────────────────────────────────┐
  Scanner  ─────────▶   │  gateway (Nginx/Traefik)  127.0.0.1:8000   │
  (sizin uygulamanız)   │  - yol bazlı yönlendirme                    │
                        │  - profil: waf-off | waf-low | waf-high     │
                        │  - TLS profilleri (:8443 / :8444 / :8445)   │
                        └───────┬─────────────────────────────────────┘
                                │ lab_net (internal bridge)
   ┌──────────┬──────────┬──────┴───┬───────────┬──────────┬───────────┐
   ▼          ▼          ▼          ▼           ▼          ▼           ▼
 php-web   node-api   flask-svc  spring-svc  go-svc    graphql-svc  crawl-lab
 (klasik)  (REST+JWT) (SSTI,     (XXE,       (SSRF,    (introspect, (SPA, WS,
                       pickle)    deser.)     race)     batching)    flows)
   │          │          │          │           │          │           │
   └──────────┴────┬─────┴──────────┴───────────┴──────────┴───────────┘
                   ▼
   ┌──────────── veri/altyapı katmanı ────────────────────────────┐
   │ mysql  postgres  mongodb  redis  elasticsearch  minio(S3)    │
   │ ldap(openldap)  mailhog(smtp)  ftp (vsftpd)  memcached       │
   └──────────────────────────────────────────────────────────────┘
   ┌──────────── lab yönetim katmanı ─────────────────────────────┐
   │ oob-collector (HTTP+DNS)   lab-control (reset/seed/mode)     │
   │ truth-api (vulns.json)     scorer (CLI + HTML rapor)         │
   │ request-logger (JSONL)     dashboard (opsiyonel)             │
   └──────────────────────────────────────────────────────────────┘
```

### 3.1 Servisler ve görevleri

| Servis | Teknoloji | Port (host) | Görev |
|---|---|---|---|
| `gateway` | Nginx (+ModSecurity profili) | 8000 / 8443 | Tek giriş noktası, WAF/TLS profilleri |
| `php-web` | PHP 8 + Apache, MySQL | via gateway `/php/` | Klasik sunucu taraflı zafiyetler |
| `node-api` | Node 18 Express + MongoDB | `/api/` | REST API, JWT, NoSQLi, prototype pollution |
| `flask-svc` | Python 3 Flask | `/py/` | SSTI, pickle/YAML deserialization, path traversal |
| `spring-svc` | Java 17 Spring Boot | `/java/` | XXE, Java deserialization, SpEL, Log4Shell benzeri (izole) |
| `go-svc` | Go | `/go/` | SSRF, race condition, HTTP smuggling hedefi |
| `graphql-svc` | Node (Apollo) veya Python (Graphene) | `/graphql` | GraphQL'e özgü zafiyetler |
| `crawl-lab` | React SPA + WebSocket + SSE | `/spa/` | Crawler zorlukları |
| `legacy-svc` | Eski Apache/PHP 5.x benzeri | `/legacy/` | Eski sürüm banner'ları, bilinen CVE'li yazılım |
| `auth-svc` | Keycloak veya özel OAuth/SAML | `/auth/` | OAuth/OIDC/SAML zafiyetleri |
| `oob-collector` | Go/Python | 9000 (HTTP), 5353/udp (DNS) | Blind zafiyet doğrulama |
| `lab-control` | Python FastAPI | 9100 | Reset, seed, mod, profil yönetimi |
| `truth-api` | FastAPI | 9101 | `vulns.json`, kategori sorguları |
| `scorer` | Python CLI | konteyner içi | Skor ve HTML rapor |

### 3.2 Ağ topolojisi
- `lab_net`: servislerin birbirine eriştiği dahili ağ.
- `data_net`: yalnızca uygulama → veritabanı. Scanner doğrudan erişemez (hariç: bilerek açık bırakılan servisler `exposed_net` üzerinde).
- `exposed_net`: bilerek açık servisler (Redis, ES, MinIO, FTP) ağ keşfi / port tarama testleri için.
- SSRF hedefleri için `internal_net`: cloud metadata taklidi (`169.254.169.254` simülatörü), dahili admin paneli.

---

## 4. Dizin Yapısı

```
vulnforge/
├── docker-compose.yml
├── docker-compose.override.example.yml
├── .env.example
├── README.md
├── plan.md
├── Makefile                        # make up / down / reset / score
├── gateway/
│   ├── nginx.conf
│   ├── profiles/{waf-off,waf-low,waf-high}.conf
│   ├── modsecurity/ (CRS ayarları)
│   └── tls/{good,weak-ciphers,expired,selfsigned}/
├── services/
│   ├── php-web/
│   │   ├── Dockerfile
│   │   ├── src/{sqli,xss,lfi,upload,cmdi,idor,csrf,redirect,auth,session,...}/
│   │   └── db/seed.sql
│   ├── node-api/
│   │   ├── Dockerfile
│   │   ├── src/routes/{users,orders,auth,files,admin,webhooks,...}.js
│   │   └── openapi.yaml
│   ├── flask-svc/
│   ├── spring-svc/
│   ├── go-svc/
│   ├── graphql-svc/
│   ├── crawl-lab/
│   ├── legacy-svc/
│   └── auth-svc/
├── infra/
│   ├── exposed/{redis,elasticsearch,minio,ftp,memcached,ldap}/
│   ├── oob-collector/
│   ├── mailhog/
│   └── internal-metadata/          # sahte cloud metadata servisi
├── lab/
│   ├── lab-control/
│   ├── truth-api/
│   ├── truth/                      # kaynak etiketlerinden üretilen çıktılar
│   │   ├── vulns.json
│   │   ├── controls.json
│   │   └── schema.json
│   └── tools/extract_truth.py      # kod etiketlerinden vulns.json üretir
├── scorer/
│   ├── scorer.py
│   ├── adapters/{zap,burp,nuclei,custom_json,sarif}.py
│   └── report_template.html
├── tests/
│   ├── smoke/                      # her zafiyetin gerçekten sömürülebildiğini doğrulayan testler
│   └── controls/                   # güvenli ikizlerin gerçekten güvenli olduğunu doğrulayan testler
└── docs/
    ├── vulnerability-catalog.md
    ├── scoring.md
    └── scanner-integration.md
```

---

## 5. Ground Truth Sistemi

### 5.1 Kod içi etiketleme
Her zafiyetli endpoint/fonksiyon üzerinde standart bir etiket bulunur (dile uygun yorum/dekoratör):

```php
// @vuln id=SQLI-001 cwe=CWE-89 owasp=A03:2021 type=error-based level=1 param=id method=GET
```
```python
@vuln(id="SSTI-003", cwe="CWE-1336", owasp="A03:2021", level=2, param="name", method="GET")
```

`tools/extract_truth.py` tüm repo'yu tarar, `vulns.json` ve `controls.json` üretir. CI bu dosyanın güncel olduğunu doğrular.

### 5.2 `vulns.json` şeması

```json
{
  "id": "SQLI-001",
  "name": "Error-based SQL Injection in product search",
  "cwe": ["CWE-89"],
  "owasp_web_2021": "A03",
  "owasp_api_2023": null,
  "service": "php-web",
  "url": "/php/sqli/products.php",
  "method": "GET",
  "parameter": "id",
  "parameter_location": "query",
  "type": "error-based",
  "difficulty": 1,
  "auth_required": false,
  "preconditions": [],
  "detection_class": "active|passive|sca|config|logic|api",
  "needs_oob": false,
  "exploit_proof": {"kind": "marker", "description": "DB hata mesajında version() görünür"},
  "references": ["https://cwe.mitre.org/data/definitions/89.html"],
  "tags": ["injection", "database", "mysql"]
}
```

### 5.3 `controls.json` (güvenli ikizler)
```json
{"id":"SQLI-001-C","twin_of":"SQLI-001","url":"/php/sqli/products_safe.php","parameter":"id","expected":"no-finding"}
```

### 5.4 Sömürü kanıt mekanizması
Scanner'ın "tespit etti" iddiası ile "gerçekten sömürebildi" ayrımı için:
- **Marker tabanlı:** Her zafiyet sömürülürse yanıtta/OOB'de benzersiz marker belirir.
- **Olay logu:** `request-logger`, sunucu tarafında "zafiyet tetiklendi" olayını (`vuln_triggered`) JSONL olarak yazar. Scorer, scanner trafiğiyle bu olayları ilişkilendirir (doğrulama düzeyi: *tespit* vs *sömürü*).

---

## 6. Zafiyet Kataloğu

Sayılar hedef minimumdur. Her satır birden fazla varyant/seviye içerir.

### 6.1 A01: Broken Access Control (hedef ≥ 40)
- IDOR (sayısal, UUID, hash'li, base64'li, sıralı olmayan ID)
- Yatay / dikey yetki yükseltme, gizli admin paneli, `X-Original-URL` / `X-Rewrite-URL` ile bypass
- HTTP method override ve verb tampering (`X-HTTP-Method-Override`)
- Forced browsing (yedek dosyalar, `/admin`, `/backup.zip`, `/.git/`, `/.svn/`, `/.DS_Store`)
- Path-based erişim kontrolü atlatma (`/admin/..;/`, büyük/küçük harf, çift slash, trailing dot)
- CORS yanlış yapılandırma (reflected origin, `null` origin, wildcard + credentials, regex bypass)
- Çok kiracılı (multi-tenant) veri sızıntısı
- Mass assignment (`isAdmin`, `role`, `balance` alanları)
- JWT ile rol manipülasyonu (bkz. A07)
- Dosya indirme erişim kontrolü eksikliği
- Parametre/Cookie ile rol belirleme (`role=admin`)
- Referer/Origin'e dayalı erişim kontrolü
- **Güvenli ikizler:** doğru yetkilendirme yapan endpoint'ler

### 6.2 A02: Cryptographic Failures (hedef ≥ 25)
- HTTP üzerinden hassas veri, HSTS yok, karma içerik (mixed content)
- Zayıf TLS profilleri: SSLv3/TLS1.0/1.1, RC4, 3DES, export cipher, zayıf DH, süresi dolmuş / self-signed / yanlış CN sertifika
- MD5/SHA1 ile tuzsuz parola hash'i, sabit tuz, düşük iterasyonlu PBKDF2
- ECB modu, sabit IV, sabit/sızmış anahtar, tahmin edilebilir token (zaman tabanlı, `rand()` tohumu)
- Padding oracle (CBC)
- Hassas verinin URL'de, localStorage'da, loglarda, hata mesajlarında bulunması
- Cookie'de hassas veri base64/düz metin
- Sertifika doğrulaması kapalı giden istekler (webhook/SSRF bağlamı)

### 6.3 A03: Injection (hedef ≥ 80)

**SQL Injection** (MySQL, PostgreSQL, SQLite, MSSQL taklidi, Oracle taklidi)
- error-based, union-based, boolean-blind, time-based blind, stacked queries, second-order, out-of-band
- Bağlamlar: sayısal, string (tek/çift tırnak), `LIKE`, `ORDER BY`, `LIMIT`, `IN()`, `INSERT`/`UPDATE`/`DELETE`, JSON alanı, header (`User-Agent`, `X-Forwarded-For`), cookie, JSON/XML body
- Filtre varyantları: boşluk filtresi, anahtar kelime filtresi (`UNION`, `SELECT`), yorum filtresi, `addslashes` / GBK wide-byte, büyük/küçük harf, çift kodlama, `/**/`

**NoSQL Injection** (MongoDB operatör enjeksiyonu `$ne`, `$gt`, `$regex`, `$where`; JSON ve form biçimleri)

**XSS**
- Reflected (HTML, attribute, JS string, URL, CSS, `<script>` içi, event handler bağlamları)
- Stored (yorum, profil, dosya adı, log görüntüleme paneli, admin paneli blind XSS)
- DOM-based (`location.hash`, `document.write`, `innerHTML`, `eval`, `postMessage`, jQuery sink'leri, `srcdoc`)
- Mutation XSS, SVG/MathML, markdown render, template literal, AngularJS sandbox escape (eski sürüm), CSP bypass senaryoları
- Filtre varyantları: tag blacklist, `script` kaldırma, tek geçişli replace, HTML entity kodlama, `htmlspecialchars` hatalı kullanım (tek tırnak)

**Command Injection** (`;`, `&&`, `|`, `` ` ``, `$()`, newline; blind time-based; blind OOB; Windows tarzı ayraçlar; argüman enjeksiyonu `--option`)

**Diğer enjeksiyonlar**
- LDAP injection, XPath injection, XQuery
- SSTI (Jinja2, Twig, Freemarker, Velocity, Thymeleaf, Smarty, ERB/Handlebars/Pug)
- Expression Language / SpEL / OGNL injection
- Header injection / CRLF injection (response splitting)
- Email header injection (SMTP, MailHog'a düşer)
- Log injection / log forging
- CSV/Formula injection
- XML injection / XXE (klasik, blind, OOB, parameter entity, SVG/DOCX/XLSX içinde, SOAP)
- Code injection (`eval`, `assert`, `preg_replace /e`, `include`)
- Host header injection (şifre sıfırlama zehirleme)
- Server-Side Includes (SSI) injection
- GraphQL injection
- Regex injection / ReDoS (hatalı regex)
- Prompt injection (opsiyonel "LLM chat" modülü: dolaylı enjeksiyon, veri sızdırma)

### 6.4 A04: Insecure Design / Business Logic (hedef ≥ 30)
- Race condition (kupon çift kullanım, bakiye çift harcama, TOCTOU) → `go-svc`
- Negatif miktar / tam sayı taşması / yuvarlama hatası
- Fiyat manipülasyonu (istemci taraflı fiyat), kupon yığma, adım atlama (ödeme akışında)
- Rate-limit yokluğu (login, OTP, şifre sıfırlama, SMS bombası taklidi)
- OTP brute-force (4/6 hane), OTP'nin yanıtta dönmesi
- Hesap numaralandırma (kullanıcı adı / e-posta farklı yanıtlar, zamanlama farkı)
- Şifre sıfırlama mantık hataları (tahmin edilebilir token, token yeniden kullanımı, Host header zehirlenmesi)
- İş akışı atlatma (çok adımlı kayıt, e-posta doğrulama atlama)
- Zayıf CAPTCHA (istemci doğrulama, token yeniden kullanımı)

### 6.5 A05: Security Misconfiguration (hedef ≥ 60)
- Eksik / yanlış güvenlik başlıkları (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP)
- `Server`, `X-Powered-By`, `X-AspNet-Version` bilgi sızıntısı
- Dizin listeleme (Apache, Nginx autoindex), varsayılan sayfalar
- Açık: `.git`, `.svn`, `.env`, `.htaccess`, `.htpasswd`, `config.php.bak`, `web.config`, `backup.sql`, `phpinfo.php`, `server-status`, `/actuator/*`, `/debug`, `/metrics`, `/swagger-ui`, `/api-docs`, `/.well-known/`, `/console` (Werkzeug), `/elmah.axd` benzeri, `/_profiler`
- Ayrıntılı hata sayfaları / stack trace, debug modu açık
- Varsayılan kimlik bilgileri (admin/admin, tomcat/tomcat, vb.)
- Gereksiz HTTP metotları (`TRACE`, `PUT`, `DELETE`, `PROPFIND`), `OPTIONS` sızıntısı
- Cookie bayrakları (HttpOnly, Secure, SameSite eksik; `Path`/`Domain` fazla geniş)
- Clickjacking (frame korumasız), clickjacking + hassas aksiyon
- Açık bulut depoları (MinIO bucket public-read, dizin listeleme)
- Açık servisler: Redis (auth yok), Elasticsearch, Memcached, MongoDB (auth yok), FTP anonim, LDAP anonim bind
- Subdomain takeover simülasyonu (CNAME → olmayan servis; yerel DNS ile)
- XXE'ye açık varsayılan XML parser ayarları
- `robots.txt` / `sitemap.xml` içinde hassas yol sızıntısı
- Çeşitli `Content-Type` yanlışlıkları (MIME sniffing)

### 6.6 A06: Vulnerable & Outdated Components (SCA, hedef ≥ 40)
- Bilinçli olarak eski sürümlü bileşenler: jQuery (1.x, 2.x, 3.3), AngularJS 1.x, Bootstrap 3, lodash (prototype pollution), moment, Handlebars, Struts, Spring (eski), Log4j 2.14, Jackson, Express/Node eski sürümler, Flask/Werkzeug eski, PHP 5.x/7.0 banner, Apache/Nginx eski banner
- JS kütüphaneleri hem sayfada hem `package.json` / `composer.json` / `requirements.txt` / `pom.xml` / `go.mod` manifest'lerinde
- Her bileşen için bilinen CVE listesi `vulns.json` içinde `cve` alanıyla
- CMS taklidi (eski WordPress/Joomla/Drupal yolları ve banner'ları) için imza testi

### 6.7 A07: Identification & Authentication Failures (hedef ≥ 45)
- Zayıf / varsayılan parola, parola politikası yok, kullanıcı adı numaralandırma
- Brute force / credential stuffing (kilitleme yok), kilitleme bypass (`X-Forwarded-For` döndürme)
- Oturum yönetimi: session fixation, tahmin edilebilir session ID, çıkışta geçersiz kılmama, URL'de session ID, uzun/sonsuz ömür, paralel oturum sınırı yok
- **JWT:** `alg=none`, zayıf HS256 sırrı (kırılabilir), RS256→HS256 karışıklığı, `kid` enjeksiyonu (SQLi / path traversal), `jku`/`jwk` başlığı enjeksiyonu, `exp` doğrulanmaması, hassas veri payload'da
- **OAuth 2.0 / OIDC:** `redirect_uri` doğrulaması zayıf, `state` yok (CSRF), implicit flow sızıntıları, PKCE yok, token sızıntısı Referer ile, scope yükseltme, açık yönlendirme zinciri
- **SAML:** imza doğrulama atlatma, XML signature wrapping, XXE (opsiyonel)
- MFA bypass (yanıt manipülasyonu, OTP yeniden kullanım, brute force, "remember me" zayıflığı)
- "Beni hatırla" çerezi tahmin edilebilir
- Basic/Digest auth zayıflıkları, API anahtarı URL'de
- Parola değiştirirken eski parola istememe, e-posta değiştirme sonrası doğrulamama
- Şifre sıfırlama: tahmin edilebilir token, token sızıntısı, Host header zehirleme

### 6.8 A08: Software & Data Integrity Failures (hedef ≥ 25)
- Güvensiz deserialization: PHP `unserialize` (POP chain), Java (`ObjectInputStream`, gadget'lı eski kütüphane), Python `pickle`, `yaml.load`, Node `node-serialize`, .NET `BinaryFormatter` (opsiyonel), Ruby `Marshal` (opsiyonel)
- SRI (Subresource Integrity) olmadan harici script/CDN
- İmzasız güncelleme / eklenti yükleme
- Prototype pollution (sunucu ve istemci tarafı)
- CI/CD ve bağımlılık karışıklığı simülasyonu (dependency confusion, `package.json` içinde)
- Cookie / parametre bütünlüğü kontrolsüz (HMAC yok)
- Insecure file upload ile kod yürütme

### 6.9 A09: Security Logging & Monitoring Failures (hedef ≥ 10)
- Başarısız girişlerin loglanmaması, log içinde hassas veri, log injection
- Herkese açık log dosyaları (`/logs/app.log`), log görüntüleyici panel (stored XSS)
- Uyarı mekanizmasının yokluğu (scanner'ın bunu gözlemlemesi için *pasif* göstergeler)

### 6.10 A10: SSRF (hedef ≥ 25)
- Klasik SSRF (URL parametresi, webhook, görsel çekme, PDF üretme, URL önizleme, import-from-URL, RSS okuyucu)
- Blind SSRF (OOB ile doğrulama)
- Cloud metadata taklidi (`169.254.169.254`, `metadata.google.internal` yerel simülasyonu)
- Filtre bypass: `localhost` varyantları, `127.1`, ondalık/octal/hex IP, IPv6, DNS rebinding (kontrollü), `@` ile URL karışıklığı, redirect zinciri, `file://`, `gopher://`, `dict://` (izinli ise)
- SSRF → dahili Redis / dahili admin paneli

### 6.11 A11: Diğer Web Zafiyetleri (OWASP dışı ama yaygın)

**Dosya işlemleri**
- LFI/RFI, path traversal (`../`, `..%2f`, `....//`, null byte (eski PHP), Windows ayraçları), zip slip
- Arbitrary file upload (uzantı, MIME, magic byte, çift uzantı, `.htaccess` yükleme, SVG içi XSS, polyglot, boyut bypass)
- Arbitrary file read / delete / write

**İstemci tarafı**
- CSRF (token yok, token sabit, token doğrulanmıyor, SameSite bypass, JSON CSRF, `Content-Type` kontrolü eksik)
- Open redirect (parametre, header, `javascript:`, protokol-relative, whitelist bypass)
- Clickjacking, tabnabbing (`target=_blank` + `noopener` yok)
- `postMessage` origin doğrulamasız, `window.name` sink'leri
- CSS injection / veri sızdırma, HTML injection (script'siz)
- Reverse tabnabbing, DOM clobbering
- Client-side prototype pollution → XSS gadget
- Hassas veri `localStorage`/`sessionStorage`/IndexedDB'de
- WebSocket: origin kontrolsüz (CSWSH), kimlik doğrulamasız, enjeksiyon

**HTTP katmanı**
- HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, HTTP/2 downgrade) → özel gateway profili
- Web cache poisoning (unkeyed header), web cache deception
- HTTP Parameter Pollution (HPP)
- Host header saldırıları, `X-Forwarded-*` güveni
- HTTP/2 ve HTTP/3 davranışları (opsiyonel), `Range` başlığı sorunları
- Slowloris benzeri / yavaş istek DoS'a duyarlı endpoint (kontrollü, opsiyonel)
- `Content-Type` karışıklığı, MIME sniffing, JSON hijacking (eski), JSONP callback enjeksiyonu

**DoS / kaynak**
- ReDoS, XML bomb (billion laughs), zip bomb (sınırlı boyutlu), GraphQL derinlik/alias DoS, sınırsız sayfalama (`limit=999999`), pahalı sorgu

**Bilgi sızıntısı**
- Yorumlarda hassas veri, kaynak haritaları (`.map`), `console.log` kalıntıları, hata mesajlarında SQL / yol / sürüm, e-posta/telefon/IP sızıntıları, API anahtarı JS içinde, kullanıcı numaralandırma
- Yedek ve geçici dosyalar (`~`, `.bak`, `.old`, `.swp`, `.orig`)

### 6.12 API Security Top 10 (2023) Eşlemesi (REST + GraphQL + SOAP + gRPC-web opsiyonel)

| API kategorisi | Uygulama örnekleri |
|---|---|
| API1 BOLA | `/api/v1/orders/{id}`, `/users/{id}/documents`, iç içe kaynaklar |
| API2 Broken Authentication | zayıf JWT, API key sızıntısı, token yenileme açığı, parola sıfırlama API'si |
| API3 BOPLA (Broken Object Property Level Auth) | aşırı veri döndürme (`passwordHash`, `ssn`), mass assignment |
| API4 Unrestricted Resource Consumption | sayfalama sınırı yok, upload boyutu sınırsız, GraphQL batching, pahalı sorgular |
| API5 BFLA | `DELETE /users/{id}` herkese açık, admin uçlarına normal kullanıcı erişimi |
| API6 Unrestricted Access to Sensitive Business Flows | kupon/hediye kartı otomasyonu, hesap oluşturma botu |
| API7 SSRF | webhook, avatar URL, import |
| API8 Security Misconfiguration | CORS, verbose error, debug endpoint, eski API sürümü açık |
| API9 Improper Inventory Management | `/api/v1` (savunmasız) ve `/api/v2` (güvenli), shadow/zombie endpoint, belgelenmemiş endpoint |
| API10 Unsafe Consumption of APIs | üçüncü taraf yanıtına körü körüne güven (mock servis ile) |

**API'ye özgü ek özellikler:** OpenAPI 3 + Swagger 2 + Postman koleksiyonu (belgeli ve **belgesiz** endpoint karışımı), GraphQL (introspection açık/kapalı, field suggestion sızıntısı, batching, alias brute-force, derinlik DoS, `__typename` bilgi sızıntısı, GraphQL üzerinden SQLi/IDOR), SOAP/WSDL (XXE, WS-Security zayıflıkları), gRPC-web (opsiyonel), WebSocket API, Server-Sent Events, API versiyonlama, içerik müzakeresi (JSON/XML/form dönüşümü ile XXE tetikleme).

### 6.13 Sunucu / Altyapı Tarafı (port & network scanner modülü varsa)
- Açık portlar ve banner'lar (FTP, SSH, Telnet taklidi, SMTP, Redis, Memcached, MongoDB, Elasticsearch, MinIO, LDAP, Docker API taklidi *(sahte, sömürülemez)*)
- Anonim FTP, varsayılan SNMP community taklidi (opsiyonel)
- Zayıf SSH yapılandırması banner'ı (gerçek zayıf SSH **konulmaz**; sadece taklit)

---

## 7. Zafiyet Seviye Sistemi

| Seviye | Tanım | Örnek (SQLi) | Ölçülen yetenek |
|---|---|---|---|
| **L0** | Güvenli kontrol | Prepared statement | Yanlış pozitif oranı |
| **L1** | Filtresiz, bariz | `WHERE id=$_GET[id]` + hata mesajı | Temel tespit |
| **L2** | Basit filtre | `UNION`/`SELECT` büyük/küçük harf filtresi | Payload çeşitliliği |
| **L3** | Güçlü filtre / bağlam | Boşluk+yorum filtresi, blind-only, JSON içinde | Encoding / bypass / blind teknikleri |
| **L4** | WAF arkasında / çok adımlı / auth gerekli | ModSecurity CRS arkasında, second-order | İleri teknikler, oturum yönetimi |

Her zafiyet için `level` alanı `vulns.json`'da bulunur; skor raporu seviye bazında kırılım verir.

---

## 8. Crawl-Lab (Tarayıcı Kapsama Testleri)

Scanner'ın **keşif** yeteneğini ölçer. Her keşfedilebilir yüzey `surface.json` içinde listelenir (kapsama metriği).

- **SPA (React + client-side routing):** `#/route` ve History API; lazy-loaded modüller; bileşen içinde gizli yönlendirmeler
- **Link türleri:** `<a>`, `<form>`, `onclick`, `data-href`, `<meta refresh>`, JS içinde dinamik oluşturulan URL'ler, `fetch/XHR/axios` ile çağrılan endpoint'ler, `import()`
- **Form zorlukları:** CSRF token'lı, çok adımlı (wizard), dinamik alanlar, dosya yükleme, captcha'lı (kolay), `multipart`, JSON gönderen formlar
- **Oturum:** login arkasında alanlar, oturum süresi dolması ve yeniden giriş, logout URL'sine basıp oturum düşürme tuzağı (scanner'ı oturumdan çıkaran link), farklı rol alanları
- **Durum bağımlı akışlar:** sepete ürün eklenmeden görünmeyen sayfalar, sıralı adımlar
- **Sonsuz/tuzak URL'ler:** takvim sonsuz sayfalama, `?page=N` sınırsız, döngüsel yönlendirmeler, çok büyük sayfa, yavaş yanıt (crawler'ın zaman aşımı yönetimi)
- **Keşif kaynakları:** `robots.txt` (Disallow'da gizli yollar), `sitemap.xml` (iç içe sitemap index), `OpenAPI/Swagger`, `.well-known/*`, JS dosyalarındaki yollar, source map, `security.txt`, HTML yorumları
- **Gerçek zamanlı:** WebSocket kanalları, SSE akışı, long polling
- **Teknik zorluklar:** `<base href>`, göreli URL tuzakları, URL fragment, iframe içi içerik, shadow DOM, canvas'ta gizli bağlantı yok (negatif kontrol), `rel=nofollow`, `Content-Type` yanlış sayfalar, ezik HTML
- **Değişken içerik:** zaman damgası/rastgele token içeren sayfalar (deduplikasyon testi), soft-404 sayfaları (200 dönen "bulunamadı"), özel 404/403/500 şablonları
- **Rate-limit ve bot koruması:** belirli istek hızı aşılınca 429 / geçici ban; `Retry-After`; basit JS challenge (opsiyonel profil)

---

## 9. WAF / Savunma Profilleri

| Profil | İçerik | Test ettiği |
|---|---|---|
| `waf-off` | Hiç koruma yok | Temel tespit |
| `waf-low` | ModSecurity CRS paranoia 1 | Basit evasion |
| `waf-high` | CRS paranoia 3-4 + özel kurallar | İleri evasion |
| `ratelimit` | IP başına istek limiti, kademeli yavaşlatma | Scanner'ın hız adaptasyonu |
| `flaky` | Rastgele 5xx/timeout/gecikme (%N) | Dayanıklılık, retry mantığı |
| `waf-honeypot` | Tuzak yollar tetiklenince IP engeli | Scanner'ın tuzaklara basmaması |

Profil seçimi: `lab-control` API veya `.env` (`WAF_PROFILE=low`).

---

## 10. Blind / Out-of-Band (OOB) Altyapısı

`oob-collector`:
- HTTP callback + DNS callback (wildcard `*.oob.lab.local`)
- Her callback için benzersiz token → `vulns.json` ile eşleşme
- API: `GET /oob/events?token=...`
- Kapsanan sınıflar: blind SQLi (DNS exfil), blind CMDi, blind XXE, blind SSRF, blind XSS (stored → admin bot tetikler), blind SSTI, log4shell benzeri JNDI lookup (yalnızca callback, gerçek RCE yok), email header injection

**Admin bot (headless Chromium):** Belirli aralıklarla stored içeriği (yorumlar, destek talepleri, log paneli) ziyaret eder → blind/stored XSS doğrulaması.

---

## 11. Lab Kontrol API'si (`lab-control`)

| Endpoint | İşlev |
|---|---|
| `POST /__lab/reset` | Tüm DB'leri seed'e döndür, dosyaları temizle, OOB olaylarını sıfırla |
| `POST /__lab/seed?profile=small\|large` | Veri hacmi (küçük/büyük) |
| `GET /__lab/vulns` | `vulns.json` |
| `GET /__lab/mode` / `PUT` | Aktif zafiyet kümesi (örn. yalnızca `owasp_a03`, `level<=2`, `service=node-api`) |
| `PUT /__lab/waf` | WAF profili değiştir |
| `GET /__lab/events` | `vuln_triggered`, scanner trafiği olayları |
| `POST /__lab/session/start` / `stop` | Test oturumu başlat; log ve istatistik penceresi (scanner çalıştırması) |
| `GET /__lab/health` | Tüm servislerin hazır olma durumu |

> `lab-control` yalnızca `127.0.0.1:9100`'de dinler ve scanner hedefi dışındadır (scanner'ın "kendi test düzeneğini taramasını" önlemek için kapsam dışı sayılır).

---

## 12. Skorlama ve Raporlama (`scorer`)

### 12.1 Girdi formatları (adapter'lar)
- Özel JSON (önerilen basit şema)
- SARIF, ZAP JSON/XML, Burp XML, Nuclei JSONL, Nikto, sqlmap çıktısı (opsiyonel)

Scanner çıktısı için minimal şema:
```json
{"findings":[{"url":"/php/sqli/products.php","method":"GET","parameter":"id","cwe":"CWE-89","type":"sqli","evidence":"..."}]}
```

### 12.2 Eşleştirme kuralı
Bulgu → zafiyet eşleşmesi: `(normalize(url), method, parameter, cwe_sınıfı)` + tolerans (path parametreleri, trailing slash, query sıralaması). Eşleşmeyen bulgular **FP**, bulgusuz zafiyetler **FN**, güvenli ikizde bulgu → **kesin FP**.

### 12.3 Metrikler
- Genel: TP, FP, FN, precision, recall, F1
- Kırılım: OWASP kategorisi, CWE, servis, seviye (L1–L4), tespit sınıfı (aktif/pasif/SCA/config/logic)
- Güvenli ikiz FP oranı (en kritik metrik)
- **Crawl kapsamı:** keşfedilen yüzey / toplam yüzey (URL, form, parametre, API endpoint, WebSocket kanalı)
- Doğrulama düzeyi: *sadece raporlandı* vs *sömürü kanıtı üretildi* (olay logu ile)
- Operasyonel: toplam süre, istek sayısı, istek/sn, hata/timeout oranı, bellek/CPU (opsiyonel), WAF engel sayısı
- Karşılaştırma: önceki koşuyla fark (regression raporu), farklı scanner sürümleri arası trend

### 12.4 Çıktı
- `report.html` (grafikler, kırılım tabloları, kaçırılan zafiyet listesi ve ipuçları)
- `report.json`, `report.csv`
- CI için eşik kontrolü: `--fail-under recall=0.80 --fail-over fp=0.05`

---

## 13. Güvenlik ve İzolasyon Önlemleri (Lab'ın kendisini güvenli tutmak)

- Tüm host portları `127.0.0.1` üzerine; `docker-compose` içinde açık uyarı banner'ı.
- Konteynerler: `cap_drop: [ALL]`, `no-new-privileges`, `pids_limit`, `mem_limit`, `cpus` limiti; mümkün olan yerlerde `read_only` + tmpfs.
- RCE sınıfı zafiyetler (CMDi, SSTI, deserialization, upload) **yalnızca ayrı, ağ erişimi kısıtlı sandbox konteynerinde** çalışır; host volume mount yok, Docker socket **asla** bağlanmaz.
- Giden ağ trafiği: SSRF/RFI senaryoları için `internal_net` dışına çıkış varsayılan olarak **kapalı** (egress firewall); gerçek internete erişim sadece açıkça `ALLOW_EGRESS=true` ile.
- Gerçek kimlik bilgisi, gerçek API anahtarı, gerçek kişi verisi yok; seed verisi tamamen sentetik.
- Sınırlı kaynaklı "DoS" zafiyetleri: tavan değerlerle (XML bomb küçük, zip bomb sınırlı) host'u çökertmeyecek şekilde.
- Log4Shell benzeri senaryo gerçek RCE yerine **JNDI lookup tetiklenip OOB callback atan simülasyon** ile yapılır.
- README'de "yalnızca izole VM'de çalıştırın" notu ve kullanım şartları.

---

## 14. Docker / Dağıtım Gereksinimleri

- Tek komut: `docker compose up -d` (alternatif: `make up`)
- `healthcheck` + `depends_on: condition: service_healthy`
- Profiller: `--profile core` (php+node+flask), `--profile full`, `--profile api`, `--profile infra`, `--profile waf`, `--profile crawl`
- İlk açılışta otomatik seed; `make reset` ile sıfırlama
- Çok mimarili (amd64/arm64) imajlar; alpine/slim tabanlı, build cache optimizasyonu
- `.env.example`: portlar, WAF profili, seviye filtresi, egress, seed hacmi
- Tahmini kaynak: `core` ≈ 2 GB RAM, `full` ≈ 6–8 GB RAM (belgelenecek)
- Kaynak tüketimini azaltmak için isteğe bağlı: tek servis çalıştırma (`docker compose up php-web mysql`)

---

## 15. Test Stratejisi (Lab'ın doğruluğu)

Lab'ın kendisinin hatasız olması şarttır; aksi halde skor anlamsız olur.

1. **Sömürülebilirlik testleri (`tests/smoke`)**: Her `vulns.json` kaydı için otomatik exploit scripti (basit payload) çalıştırılır; zafiyetin gerçekten tetiklendiği doğrulanır.
2. **Güvenlik testleri (`tests/controls`)**: Her güvenli ikize aynı payload'lar gönderilir; **hiçbirinin** tetiklenmediği doğrulanır.
3. **Şema testi**: `vulns.json` JSON Schema ile doğrulanır; `url`'lerin gerçekten var olduğu kontrol edilir.
4. **Referans scanner çalıştırması**: ZAP, Nuclei, sqlmap gibi bilinen araçlarla tarama; sonuçlar "baseline" olarak saklanır (kendi scanner'ınızla kıyas için).
5. **Reset testi**: Reset sonrası durumun birebir aynı olduğu doğrulanır (hash karşılaştırma).
6. **CI**: GitHub Actions ile her PR'da build + smoke + controls.

---

## 16. Geliştirme Yol Haritası (Fazlar)

| Faz | Kapsam | Çıktı / Kabul kriteri |
|---|---|---|
| **0** | İskelet: repo, compose, gateway, `lab-control`, ground-truth etiket sistemi, `extract_truth.py` | `docker compose up` çalışır, boş `vulns.json` üretilir |
| **1** | `php-web` + MySQL: SQLi, XSS, CMDi, LFI, upload, CSRF, redirect, IDOR, auth/session | ≥ 80 zafiyet + güvenli ikizler, smoke testleri geçer |
| **2** | `scorer` v1 + özel JSON adapter | Basit bir koşuda precision/recall raporu |
| **3** | `node-api` + MongoDB: REST, JWT, NoSQLi, BOLA/BFLA/BOPLA, mass assignment, prototype pollution, OpenAPI | API Top 10 kapsaması |
| **4** | `flask-svc`: SSTI, pickle, YAML, path traversal, SSRF | ≥ 30 zafiyet |
| **5** | `oob-collector` + admin bot (blind SQLi/CMDi/XXE/SSRF/XSS) | OOB doğrulama çalışır |
| **6** | `crawl-lab` (SPA, WS, çok adımlı akış, tuzaklar) + `surface.json` kapsama metriği | Crawl kapsama raporu |
| **7** | `spring-svc` (XXE, deserialization, SpEL, JNDI simülasyonu) + `go-svc` (race, SSRF) | ≥ 30 zafiyet |
| **8** | `graphql-svc` + SOAP + WebSocket API | GraphQL'e özgü zafiyetler |
| **9** | `auth-svc`: OAuth/OIDC/SAML zafiyetleri | Kimlik doğrulama akışı testleri |
| **10** | Gateway profilleri: WAF, rate-limit, flaky, TLS profilleri, request smuggling, cache poisoning | Çok katmanlı savunma testleri |
| **11** | `legacy-svc` + SCA manifest'leri + CVE eşlemesi + exposed infra (Redis/ES/MinIO/FTP/LDAP) | Config/SCA/port-scan kapsaması |
| **12** | Skorlama v2: adapter'lar (ZAP, Burp, Nuclei, SARIF), HTML rapor, regresyon karşılaştırması, CI eşikleri | Tam raporlama |
| **13** | Dokümantasyon, `vulnerability-catalog.md` (otomatik üretilmiş tablo), sürümleme, public release | v1.0 |

---

## 17. Hedef Zafiyet Sayıları (v1.0)

| Alan | Minimum zafiyet (L1–L4 varyantlar dahil) |
|---|---|
| Injection (SQLi, NoSQLi, XSS, CMDi, SSTI, XXE, LDAP, vb.) | 120 |
| Broken Access Control / IDOR / BOLA | 45 |
| Authentication / Session / JWT / OAuth / SAML | 50 |
| Crypto failures | 25 |
| Security misconfiguration & info disclosure | 70 |
| SSRF | 25 |
| Deserialization / integrity | 25 |
| Business logic / race / rate limit | 30 |
| Client-side (CSRF, redirect, DOM, postMessage, clickjacking, WS) | 40 |
| HTTP katmanı (smuggling, cache, HPP, host header, CRLF) | 20 |
| SCA / outdated components | 40 |
| API'ye özgü (GraphQL, SOAP, REST) | 40 |
| File (LFI/RFI, upload, traversal) | 30 |
| DoS / kaynak tüketimi | 10 |
| **Toplam** | **≈ 570+** (her biri için güvenli ikiz: ≈ 570+ kontrol) |

---

## 18. LLM ile Geliştirme: Aşama Aşama Prompt Şablonları

> Hepsini tek seferde istemeyin. Her prompt'a önce `plan.md`'yi bağlam olarak verin ve **tek bir fazı** isteyin.

### Ortak sistem prompt'u
```
You are a senior application security engineer and full-stack developer.
Context: we are building "VulnForge Lab", an intentionally vulnerable web
application suite used ONLY to benchmark our own web vulnerability scanner,
in an isolated local Docker environment. The attached plan.md defines the
architecture, ground-truth system, level system and vulnerability catalog.
Follow it strictly. Rules:
- Every vulnerability must carry a machine-readable @vuln tag (id, cwe, owasp,
  type, level, param, method) so vulns.json can be auto-generated.
- Every vulnerable endpoint must have a safe "control twin".
- Use synthetic data only. No real secrets. No outbound network by default.
- Bind to 127.0.0.1. Add resource limits and healthchecks.
- After writing code, also write the smoke test that proves exploitability
  and the control test that proves the twin is safe.
Output complete, runnable files with their paths.
```

### Faz prompt'ları (örnekler)
1. **Faz 0:** "Create the repo skeleton, docker-compose.yml with profiles, gateway Nginx config with waf-off profile, lab-control FastAPI service (reset/seed/mode/health) and tools/extract_truth.py that scans @vuln tags and emits vulns.json + controls.json validated against schema.json."
2. **Faz 1:** "Implement php-web service: MySQL seed, and the SQL injection module with variants error/union/boolean-blind/time-blind/second-order across contexts (numeric, string, LIKE, ORDER BY, header, cookie, JSON body) at levels L1–L4 plus L0 safe twins. Include @vuln tags, smoke tests and control tests."
3. **Faz 3:** "Implement node-api with MongoDB following OWASP API Top 10 2023: BOLA, BOPLA, BFLA, mass assignment, JWT weaknesses (none alg, weak secret, kid injection, alg confusion), NoSQLi, prototype pollution, SSRF webhook, rate-limit gaps; v1 vulnerable and v2 secure; publish partial OpenAPI and keep undocumented shadow endpoints."
4. **Faz 5:** "Implement oob-collector (HTTP+DNS) and the headless-Chromium admin bot; wire blind SQLi/CMDi/XXE/SSRF/XSS scenarios and record oob events in lab-control."
5. **Faz 6:** "Implement crawl-lab: React SPA with client-side routing, lazy modules, multi-step wizard, CSRF-token forms, logout trap, infinite pagination trap, soft-404, WebSocket + SSE channels, robots/sitemap/openapi discovery; emit surface.json listing every discoverable URL/form/param."
6. **Faz 12:** "Implement scorer with adapters (custom JSON, SARIF, ZAP, Burp, Nuclei), matching rules with URL normalization, metrics breakdown (OWASP, CWE, level, service), crawl coverage, control-twin FP rate, exploit-proof verification from event logs, HTML + JSON report and CI thresholds."

---

## 19. Önerilen Yaklaşım ve Dikkat Edilecekler

- **Önce hazır hedefleri kullanın, sonra kendinizinkini büyütün:** Juice Shop, DVWA, bWAPP, crAPI, DVGA, WebGoat'ı `docker-compose` ile başlatıp scanner'ınızla baseline alın; VulnForge'u bunların *eksik bıraktığı* alanlar (ground truth, FP ölçümü, OOB, crawl, WAF) için geliştirin. İsterseniz `scorer`'ın adapter'ı ile hazır hedefler için de kısmi ground truth tanımlayabilirsiniz.
- **Dil seçimi stratejik:** Scanner'ınızın dil/framework bağımsızlığını ölçmek için çok dilli yapı önemlidir.
- **Kalite > Sayı:** 500 yüzeysel zafiyet yerine, doğruluğu test edilmiş, ground truth'u kesin 300 zafiyet daha değerlidir. Smoke + control testleri bu yüzden zorunludur.
- **Scanner'ı tek bir hedefe overfit etmeyin:** Seviye/varyant çeşitliliği ve rastgele "mod" kombinasyonları ile (`/__lab/mode`) farklı koşular yapın; her koşuda hedef farklı alt küme olsun.
- **Sürümleyin:** Lab sürümü + scanner sürümü + skor üçlüsünü saklayın ki gelişimi izleyebilesiniz.
- **Yasal/etik:** Bu laboratuvarı yalnızca kendi ortamınızda kullanın; içindeki teknikleri başkalarının sistemlerinde yetkisiz kullanmayın.

---

## 20. Sonraki Adım Önerisi

1. Faz 0'ı (iskelet + ground truth sistemi + `lab-control`) üretmek
2. Faz 1'i (PHP + MySQL, ilk ~80 zafiyet) üretmek
3. Faz 2 ile ilk scorer çalışır hale gelir; scanner'ınızla ilk ölçümü almak

Scanner'ınızın geliştirildiği dil, desteklediği çıktı formatı (JSON/SARIF/XML) ve odak alanları (yalnızca DAST mi, API/SCA/port tarama da var mı) belirlendiğinde `scorer` adapter'ı ve fazların önceliği buna göre ayarlanabilir.
