# VulnForge Lab

> **UYARI — kasıtlı olarak zafiyetli yazılım.**
> VulnForge Lab, web zafiyet tarayıcılarını ölçmek için geliştirilmiştir. Yalnızca
> kendi kontrolünüzdeki bir makinede ve izole bir ağda çalıştırın. İnternete
> açmayın, üretim ortamında kullanmayın. Tüm host portları varsayılan olarak
> `127.0.0.1` adresine bağlanır.

VulnForge Lab; tek bir URL üzerinden erişilebilen gerçekçi bir e-ticaret sitesi
(**ShopForge**) olarak sunulan çok dilli, kasıtlı olarak zafiyetli web
uygulamasıdır.

| | |
|---|---|
| **Durum** | v2.0 — tam profilde 9 konteyner |
| **Zafiyet sayısı** | 99 (L1–L3) ve 99 güvenli kontrol ikizi |
| **Scanner portalı** | `http://127.0.0.1:8000/` — ShopForge e-ticaret sitesi |
| **Container sayısı** | `full` ve `core` 9, `api` ve `waf` 5'er |
| **Lisans** | **Yalnızca AGPL-3.0** |
| **Geliştirici** | Cuma KURT — [cumakurt@gmail.com](mailto:cumakurt@gmail.com) |

- LinkedIn: <https://www.linkedin.com/in/cuma-kurt-34414917/>
- GitHub: <https://github.com/cumakurt/vulnforge>

---

## 1. Hızlı başlangıç

```bash
git clone https://github.com/cumakurt/vulnforge.git
cd vulnforge
./docker_install.sh          # 9 konteyner başlatır (full profil)
```

Kurulum betiği ana makinenin işletim sistemini algılar, Docker'ı doğrular,
boş bir port seçer, imajları derler ve smoke testlerini çalıştırır.

```bash
# Opsiyonel bayraklar
./docker_install.sh --port 18000 --yes --skip-tests
```

| Bayrak | Varsayılan | Açıklama |
|---|---|---|
| `--profile core\|full\|api\|waf` | `full` | Compose profili |
| `--port <n>` | `8000` | Gateway HTTP portu |
| `--yes` | false | Paket kurulum onayını atla |
| `--skip-build` | false | Mevcut imajları kullan |
| `--skip-tests` | false | Smoke suite'i atla |

### Manuel başlatma

```bash
cp .env.example .env
docker compose --profile full up -d --build
```

Mevcut bir kurulumu yükseltiyorsanız eski ShopForge konteynerini kaldırmak
için Compose başlatma komutuna `--remove-orphans` ekleyin.

### Durdurma / sıfırlama

```bash
make down      # tüm container'ları durdur
make reset     # eski lab verilerini ve olayları sıfırla; ShopForge verileri korunur
```

---

## 2. Scanner hedefi — ShopForge portalı

**Tarayıcınızı tek bir URL'ye yönlendirin:**

```
http://127.0.0.1:8000/
```

ShopForge; kayıt, oturum açma/kapatma, profil düzenleme, sepet, istek listesi,
sipariş oluşturma ve takip etme, destek talepleri, blog yorumları ve bülten
aboneliği işlemlerinin çalıştığı bir mağazadır. Yönetici panelinden kullanıcı,
ürün ve sipariş yönetimi yapılabilir. İlk açılışta
`services/shopforge/catalog.json` dosyasından 16 kurgusal ürün yüklenir;
değişiklikler SQLite veritabanında ve kalıcı Docker volume'unda saklanır.

Mağaza sayfalarında zafiyet adları, saldırı örnekleri, test hesapları veya
tanılama ipuçları gösterilmez. Yapılandırma, sentetik hesaplar, kalıcılık ve
tarama kapsamı için [ShopForge rehberine](docs/shopforge.md) bakın.

Kurulumu `--port 18000` ile yaptıysanız adres `http://127.0.0.1:18000/` olur.
Tarama kapsamı, tarayıcının gezinme ve oturum ayarlarına bağlıdır. `/` üzerinden
başlayan tarama mağazayı dolaşır; eski lab servislerini de kapsamak için aşağıdaki
yolları ve [zafiyet kataloğunu](docs/tr/zafiyet-katalogu.md) kullanın.

| Yol | Servis | Zafiyet grupları |
|---|---|---|
| `/` → `/products`, `/search`, … | gateway (ShopForge) | Gezinti yüzeyi |
| `/php/` | php-web (PHP 8 + MySQL) | SQLi, XSS, CMDi, LFI, Upload, CSRF, IDOR, Auth |
| `/api/` | node-api (Node 20) | BOLA, BOPLA, BFLA, Mass assignment, JWT, NoSQLi, SSRF |
| `/graphql` | node-api (Node 20) | Introspection, batching, alias DoS, BOLA |
| `/spa/` | node-api (Node 20) | SPA routing, robots, source map, soft-404, SSE, CSWSH |
| `/py/` | flask-svc (Python) | SSTI, Pickle RCE, YAML, path traversal, SSRF, CMDi, ReDoS |
| `/auth/` | flask-svc (Python) | OAuth redirect_uri, state, PKCE, SAML, enumeration |
| `/legacy/` | flask-svc (Python) | Eski jQuery, yedek dosya, `.git`, varsayılan kimlik |
| `/java/` | spring-svc (Java 17) | XXE, XMLDecoder RCE, EL enjeksiyonu, JNDI, zayıf kripto |
| `/go/` | go-svc (Go 1.22) | SSRF, race condition, path traversal, CMDi, OTP kaba kuvvet |

### Pasif tarama örnekleri

`/scan-fixtures/{case}/{variant}` adresine doğrudan istek gönderin. Aşağıdaki
senaryolardan birini ve varyant olarak `sample-a` veya `sample-b` kullanın.
Örnek: `http://127.0.0.1:18000/scan-fixtures/version-header/sample-a`.
Sample A beklenen sentetik sinyali içerir; Sample B kontrol yanıtıdır.
Bir örnek dizin sayfası sunulmaz: `/scan-fixtures` 404 döndürür ve mağazadan
örnek yanıtlarına bağlantı verilmez.

- `version-header` örneğinde Sample A, `X-Powered-By` başlığında kurgusal bir sürüm gösterir. İki yanıt da HTTP 200 ve aynı gövdeyi döndürür.
- `error-detail` örneğinde Sample A, kurgusal bir hata izi gösterir. İki yanıt da HTTP 500 döndürür.
- `internal-hostname` örneğinde Sample A, kurgusal bir `.invalid` ana makine adı içerir. İki yanıt da HTTP 200 döndürür.

Pasif taramayı altı örnek yanıt URL'siyle başlatıp bulguları yukarıdaki
beklentilerle karşılaştırın. Katalog puanlayıcısı bu örneklerin
bulgularını eşleşmemiş sayar. Katalog taramalarını puanlarken bu öneki kapsam
dışında tutun.

### Demo kimlik bilgileri

| Servis | Kullanıcı | Şifre |
|---|---|---|
| ShopForge yöneticisi | `admin` | `admin123` |
| ShopForge müşterileri | `alice`, `bob` | `alice123` |
| PHP web / Node API / OAuth | `alice` | `password1` |
| PHP admin | `admin` | `admin123` |
| Legacy admin | `admin` | `admin` (kasıtlı varsayılan kimlik) |

Bu hesaplar yalnızca yerel laboratuvar için üretilmiştir. İlk başlatmadan önce
`SHOPFORGE_ADMIN_PASSWORD` ve `SHOPFORGE_USER_PASSWORD` değişkenleriyle ShopForge
başlangıç şifrelerini belirleyebilirsiniz. Mevcut hesapların kayıtlı şifreleri
korunur. Portal oturumları ve eski servislerin token'ları birbirinden ayrıdır.

---

## 3. Altyapı servisleri (scanner kapsam dışı)

| Endpoint | Amaç |
|---|---|
| `http://127.0.0.1:9100/__lab/health` | Servis sağlık durumu |
| `http://127.0.0.1:9100/__lab/vulns` | Ground truth (99 zafiyet) |
| `http://127.0.0.1:9100/__lab/events` | Tetiklenen zafiyet olayları |
| `http://127.0.0.1:9100/__lab/docs` | İnteraktif API dokümantasyonu |
| `curl -X POST http://127.0.0.1:9100/__lab/reset` | Eski lab verilerini ve olayları sıfırla; ShopForge verilerini koru |
| `http://127.0.0.1:9000/` | OOB geri çağrı toplayıcı |

---

## 4. Container mimarisi (v2.0)

`full` profili dokuz konteyner çalıştırır. Nginx ve ShopForge aynı gateway
konteynerinde çalışır. ShopForge konteynerin loopback arayüzünü dinler. İki
süreçten biri beklenmedik şekilde durursa gateway yeniden başlar. Diğer
servisler mevcut konteyner ve ağ sınırlarını korur.

| # | Container | Rol | Zafiyet sayısı |
|---|---|---|---|
| 1 | `vulnforge-gateway` | Nginx proxy + TLS + WAF + ShopForge | yönlendirme |
| 2 | `vulnforge-lab-control` | Kontrol düzlemi + IMDSv1 SSRF hedefi | — |
| 3 | `vulnforge-oob-collector` | HTTP + DNS OOB toplayıcı | — |
| 4 | `vulnforge-php-web` | PHP 8 / Apache | 26 |
| 5 | `vulnforge-mysql` | MySQL 8 (php-web için gerekli) | — |
| 6 | `vulnforge-node-api` | Node.js 20 (API + GraphQL + SPA birleştirildi) | 28 |
| 7 | `vulnforge-flask-svc` | Python Flask (PY + OAuth + Legacy birleştirildi) | 25 |
| 8 | `vulnforge-spring-svc` | Java 17 (JVM'e özgü zafiyetler) | 10 |
| 9 | `vulnforge-go-svc` | Go 1.22 (goroutine race, debug.Stack) | 10 |

### Birleştirilen servisler

| Kaldırılan container | Birleştirildi | Neden |
|---|---|---|
| `crawl-lab` | `node-api` | Aynı runtime, `/spa/*` rotaları eklendi |
| `graphql-svc` | `node-api` | Aynı runtime, `/graphql` rotaları eklendi |
| `auth-svc` | `flask-svc` | Aynı runtime, `/auth/*` rotaları eklendi |
| `legacy-svc` | `flask-svc` | Aynı runtime, `/legacy/*` rotaları eklendi |
| `internal-metadata` | `lab-control` | Aynı runtime; `169.254.169.100` fixed IP `internal_net`'te |

### Kaldırılan container'lar

| Kaldırılan | Neden |
|---|---|
| `postgres` | flask-svc/spring-svc env değişkeni tanımlı ama kod asla bağlanmıyor |
| `mongodb` | node-api in-memory NoSQL operatör simülatörü kullanıyor |
| `redis` | go-svc env değişkeni tanımlı ama kod in-memory Go struct kullanıyor |
| `mailhog` | Hiçbir zafiyet doğrudan SMTP test etmiyor |

---

## 5. Doğrulama

Çalışan gateway üzerinde portalı ve sentetik kataloğu kontrol etmek için
`python3 tests/test_shopforge.py` çalıştırın. HTTP portu farklıysa `BASE_URL`
ortam değişkenini ayarlayın.

```bash
pip install -r tests/requirements.txt

make smoke      # 99 zafiyet tetiklenmeli  → 99/99 geçiş
make controls   # 99 güvenli ikiz korunmalı → 99/99 geçiş
make test       # her iki suite (198 kontrol)
```

---

## 6. Zafiyet kataloğu özeti

| Grup | ID'ler | OWASP | Servis |
|---|---|---|---|
| SQL Enjeksiyonu | SQLI-001..007 | A03 | php-web |
| XSS | XSS-001..003 | A03 | php-web |
| Kimlik Doğrulama | AUTH-001..004 | A07 | php-web |
| Komut Enjeksiyonu | CMDI-001..002 | A03 | php-web |
| IDOR | IDOR-001..002 | A01 | php-web |
| LFI / Path Traversal | LFI-001 | A01 | php-web |
| CSRF | CSRF-001 | A01 | php-web |
| API Erişim Kontrolü | API-001..004 | A01 | node-api |
| API Enjeksiyonu | API-005, API-008 | A03/A08 | node-api |
| GraphQL | GQL-001..006 | A01..A05 | node-api |
| SPA / Crawl | CRAWL-001..008 | A01..A05 | node-api |
| Python / SSTI | PY-001..011 | A01..A08 | flask-svc |
| OAuth / SAML | OAUTH-001..007 | A07 | flask-svc |
| Legacy / SCA | LEG-001..007 | A05..A07 | flask-svc |
| Java / XXE | JAVA-001..010 | A02..A08 | spring-svc |
| Go / Race | GO-001..011 | A01..A10 | go-svc |

Tam liste: [docs/vulnerability-catalog.md](docs/vulnerability-catalog.md)

---

## 7. Makefile referansı

```bash
make install     # tek komutla kurulum
make up          # tüm servisleri başlat
make down        # tüm servisleri durdur
make reset       # veritabanlarını sıfırla
make smoke       # smoke suite çalıştır
make controls    # controls suite çalıştır
make test        # her iki suite
make score       # örnek bulguları puanla
make truth       # lab/truth/vulns.json yeniden üret
make catalog     # zafiyet kataloğu dökümanlarını yeniden üret
```
