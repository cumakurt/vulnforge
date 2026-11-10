# VulnForge Lab

> **UYARI — kasıtlı olarak zafiyetli yazılım.**
> VulnForge Lab, web zafiyet tarayıcılarını ölçmek için geliştirilmiştir. Yalnızca
> kendi kontrolünüzdeki bir makinede ve izole bir ağda çalıştırın. İnternete
> açmayın, üretim ortamında kullanmayın. Tüm host portları varsayılan olarak
> `127.0.0.1` adresine bağlanır.

VulnForge Lab; makine tarafından okunabilen ground truth, her zafiyet için
güvenli bir "kontrol ikizi", sömürü tetikleme olay günlüğü ve tarayıcı çıktısını
precision/recall raporuna dönüştüren bir scorer içeren çok dilli, kasıtlı olarak
zafiyetli uygulama setidir.

| | |
|---|---|
| **Durum** | v1.0 — `full` profili uçtan uca çalışır |
| **Zafiyet sayısı** | 99 (L1–L3) ve 99 güvenli kontrol ikizi |
| **Servisler** | 9 uygulama katmanı + altyapı + lab araçları |
| **Lisans** | **Yalnızca AGPL-3.0** |
| **Geliştirici** | Cuma KURT — [cumakurt@gmail.com](mailto:cumakurt@gmail.com) |

- LinkedIn: <https://www.linkedin.com/in/cuma-kurt-34414917/>
- GitHub: <https://github.com/cumakurt/vulnforge>

---

## 1. Hızlı başlangıç

### Tek komutla kurulum (önerilen)

```bash
git clone https://github.com/cumakurt/vulnforge.git
cd vulnforge
./docker_install.sh                 # core profili
./docker_install.sh --profile full  # tüm servisler
```

Kurulum script'i:

1. işletim sistemini ve paket yöneticisini tespit eder (apt, dnf, yum, pacman, zypper, apk, brew),
2. Docker, Compose eklentisi, curl ve python3 varlığını kontrol eder,
3. **eksik paket varsa kurulumdan önce kullanıcıdan onay ister**,
4. gerektiğinde `.env` oluşturur ve boş bir HTTP portu otomatik seçer,
5. seçilen profili derler ve başlatır,
6. health check sonuçlarını bekler ve erişim bilgilerini yazdırır,
7. isteğe bağlı olarak smoke testlerini çalıştırıp lab'ın sömürülebilir olduğunu kanıtlar.

Parametreler:

| Parametre | Anlamı |
|---|---|
| `--profile core\|full\|api\|infra\|waf\|crawl` | Başlatılacak Compose profili |
| `--port <port>` | Gateway HTTP portu (varsayılan `8000`, doluysa sonraki boş port) |
| `--https-port <port>` | Gateway HTTPS portu (varsayılan `8443`) |
| `--lab-port <port>` | `lab-control` portu (varsayılan `9100`) |
| `--yes` | Hiç soru sorma (CI / otomatik kurulum) |
| `--skip-build` | Mevcut imajları kullan |
| `--skip-tests` | Smoke testlerini çalıştırma |

### Manuel başlatma

```bash
cp .env.example .env
docker compose --profile full up -d --build
curl -X POST http://127.0.0.1:9100/__lab/reset
```

### Durdurma / sıfırlama

```bash
make down      # stack'i durdur
make reset     # veritabanları, yüklemeler ve olayları sıfırla
```

---

## 2. Tarayıcı nereye yönlendirilir?

Tüm servisler tek bir gateway üzerinden sunulur.

| Ne | Adres |
|---|---|
| Gateway (tarayıcı hedefi) | `http://127.0.0.1:8000/` |
| HTTPS (self-signed) | `https://127.0.0.1:8443/` |
| Lab control (tarayıcı kapsamı dışı) | `http://127.0.0.1:9100/` |
| OOB collector (full profil) | `http://127.0.0.1:9000/` |

| Yol | Servis | Kapsam |
|---|---|---|
| `/php/` | php-web (PHP 8 + MySQL) | SQLi, XSS, CMDi, LFI, upload, CSRF, IDOR, auth |
| `/api/` | node-api (Node 20) | BOLA, BOPLA, BFLA, mass assignment, JWT, NoSQLi, SSRF |
| `/py/` | flask-svc (Python/Flask) | SSTI, pickle, YAML, path traversal, SSRF, CMDi, ReDoS |
| `/java/` | spring-svc (Java 17) | XXE, deserialization, EL injection, JNDI, zayıf kripto |
| `/go/` | go-svc (Go) | SSRF, race condition, traversal, CMDi, OTP brute force |
| `/graphql` | graphql-svc (Node) | introspection, batching, alias DoS, BOLA |
| `/spa/` | crawl-lab (Node) | SPA routing, robots, source map, soft-404, SSE |
| `/legacy/` | legacy-svc (Python) | eski jQuery, yedek dosyalar, `.git`, varsayılan parola |
| `/auth/` | auth-svc (Python) | OAuth redirect_uri, state, PKCE, SAML, numaralandırma |

Güvenli ikizler her zafiyetli endpoint'in yanında bulunur ve
[`docs/tr/zafiyet-katalogu.md`](docs/tr/zafiyet-katalogu.md) içinde listelenir.

### Örnek hedefler

```bash
curl 'http://127.0.0.1:8000/php/sqli/products.php?id=1'
curl 'http://127.0.0.1:8000/api/v1/products?limit=20'
curl 'http://127.0.0.1:8000/py/ssti?name=World'
curl 'http://127.0.0.1:8000/graphql' -H 'content-type: application/json' -d '{"query":"{ hello }"}'
```

### Sentetik kimlik bilgileri

| Servis | Kimlik bilgisi |
|---|---|
| php-web / node-api / auth-svc | `alice` / `password1` |
| php-web admin | `admin` / `admin123` |
| legacy-svc | `admin` / `admin` (kasıtlı varsayılan parola) |

Tüm veriler sentetiktir. Gerçek kişisel veri, secret veya API anahtarı
içermez.

---

## 3. Benchmark nasıl çalışır?

### 3.1 Kaynak etiketlerinden ground truth

Her zafiyetli endpoint ve güvenli ikizi kaynak kodda etiketlenir:

```php
// @vuln id=SQLI-001 name="Error-based SQL Injection in product lookup" cwe=CWE-89 owasp=A03:2021 type=error-based level=1 param=id method=GET service=php-web url=/php/sqli/products.php param_loc=query needs_oob=false auth=false detection=active tags=injection,database,mysql proof_kind=marker proof_desc="MySQL error visible"
// @control id=SQLI-001-C twin_of=SQLI-001 url=/php/sqli/products_safe.php method=GET param=id service=php-web param_loc=query
```

Makine tarafından okunabilen truth dosyalarını yeniden üretin:

```bash
make truth      # -> lab/truth/vulns.json + controls.json (doğrulanır)
make catalog    # -> docs/vulnerability-catalog.md + docs/tr/zafiyet-katalogu.md
```

Doğrulayıcı; tekrarlanan id, bilinmeyen servis, geçersiz seviye, tanımsız
kontrol referansı ve **eksik ikiz** durumlarını raporlar.

### 3.2 Seviyeler

| Seviye | Anlamı |
|---|---|
| L0 | Güvenli kontrol (yanlış pozitif olarak ölçülür) |
| L1 | Filtresiz, bariz |
| L2 | Basit filtre / yalnızca blind |
| L3 | Güçlü filtre, çok adımlı veya bağlam bağımlı |
| L4 | WAF arkasında / ağır bağlam bağımlı (rezerve) |

### 3.3 Sömürü kanıtı

Zafiyetli endpoint'ler sömürü yolu tetiklendiğinde `lab_trigger(vuln_id)`
çağırır. `lab-control` bunları `vuln_triggered` olayı olarak kaydeder; scorer bu
sayede **raporlanan** ile **gerçekten sömürülen** ayrımını yapar.

### 3.4 Doğrulama testleri

```bash
pip install -r tests/requirements.txt

make smoke      # her zafiyet sömürülebilir olmalı
make controls   # her güvenli ikiz aynı payload'ı reddetmeli
make test       # ikisi birlikte (198 kontrol)
```

Sağlıklı bir `full` profilinde beklenen sonuç:

```
=== SMOKE ===
99 test(s) run, 0 failure(s)

=== CONTROLS ===
99 test(s) run, 0 failure(s)
```

---

## 4. Skorlama

```bash
python3 scorer/scorer.py \
  --findings scanner-results.json \
  --format custom_json \
  --truth-dir lab/truth \
  --out-dir scorer/out \
  --events http://127.0.0.1:9100/__lab/events \
  --fail-under recall=0.80 --fail-over fp=0.05
```

Adapter'lar: `custom_json`, `sarif`, `zap`, `nuclei`.
Çıktılar: `report.html`, `report.json`, `report.csv`.

Metrikler: TP/FP/FN, precision/recall/F1, OWASP/CWE/servis/seviye kırılımı,
güvenli ikiz yanlış pozitif oranı ve tespit–sömürü karşılaştırması.

Ayrıntılar: [docs/tr/skorlama.md](docs/tr/skorlama.md) ve
[docs/tr/tarayici-entegrasyonu.md](docs/tr/tarayici-entegrasyonu.md).

---

## 5. Lab control API

`lab-control` yalnızca `127.0.0.1:9100` üzerinde dinler ve tarayıcı kapsamı
dışındadır.

| Endpoint | Amaç |
|---|---|
| `POST /__lab/reset` | Tüm servisleri seed durumuna döndür |
| `POST /__lab/seed?profile=small\|large` | Veri hacmini seç |
| `GET /__lab/vulns` | Filtrelenmiş ground truth |
| `GET /__lab/controls` | Güvenli ikizler |
| `GET/PUT /__lab/mode` | Servis, OWASP kategorisi ve seviyeye göre filtrele |
| `GET/PUT /__lab/waf` | WAF profilini seç |
| `GET/POST /__lab/events` | Sömürü tetikleme olay günlüğü |
| `POST /__lab/session/start\|stop` | Zamanlı ölçüm oturumu |
| `GET /__lab/health` | Tüm servislerin sağlığı |

---

## 6. Dizin yapısı

```
vulnforge/
├── docker_install.sh          tek komutla kurulum ve başlatma
├── docker-compose.yml         profiller, ağlar, kaynak limitleri
├── Makefile                   install/up/down/reset/truth/catalog/test/score
├── LICENSE                    yalnızca AGPL-3.0
├── NOTICE                     geliştirici ve lisans özeti
├── README.md / README.tr.md   İngilizce ve Türkçe genel bakış
├── gateway/                   Nginx giriş noktası, WAF/TLS profilleri
├── services/
│   ├── php-web/               SQLi, XSS, CMDi, LFI, upload, CSRF, IDOR, auth
│   ├── node-api/              REST API ve OWASP API Top 10
│   ├── flask-svc/             SSTI, deserialization, SSRF, ReDoS
│   ├── spring-svc/            XXE, XMLDecoder, EL injection, JNDI
│   ├── go-svc/                SSRF, race condition, iş mantığı
│   ├── graphql-svc/           GraphQL'e özgü zafiyetler
│   ├── crawl-lab/             crawler kapsama yüzeyi
│   ├── legacy-svc/            eski bileşenler ve açık dosyalar
│   └── auth-svc/              OAuth / OIDC / SAML zafiyetleri
├── infra/                     OOB collector, metadata simülatörü, mailhog, açık servisler
├── lab/
│   ├── lab-control/           reset, seed, mode, events, sessions
│   ├── tools/                 extract_truth.py, generate_catalog.py
│   └── truth/                 üretilen vulns.json, controls.json, schema.json
├── scorer/                    adapter'lar + rapor üreteci
├── tests/                     smoke/control runner ve payload tanımları
└── docs/                      İngilizce dokümanlar + docs/tr Türkçe sürümleri
```

---

## 7. Dokümantasyon

| İngilizce | Türkçe |
|---|---|
| [docs/installation.md](docs/installation.md) | [docs/tr/kurulum.md](docs/tr/kurulum.md) |
| [docs/scoring.md](docs/scoring.md) | [docs/tr/skorlama.md](docs/tr/skorlama.md) |
| [docs/scanner-integration.md](docs/scanner-integration.md) | [docs/tr/tarayici-entegrasyonu.md](docs/tr/tarayici-entegrasyonu.md) |
| [docs/vulnerability-catalog.md](docs/vulnerability-catalog.md) | [docs/tr/zafiyet-katalogu.md](docs/tr/zafiyet-katalogu.md) |
| [docs/security.md](docs/security.md) | [docs/tr/guvenlik.md](docs/tr/guvenlik.md) |
| [README.md](README.md) | [README.tr.md](README.tr.md) |

---

## 8. Güvenlik modeli

- Tüm host portları `127.0.0.1` adresine bağlanır; dışarıya açmayın.
- Konteynerler `no-new-privileges` ve CPU/bellek limitleriyle çalışır.
- `data_net` ve `internal_net` dahili Docker ağlarıdır.
- RCE sınıfı senaryolar yalnızca konteyner içinde zararsız komutlar çalıştırır;
  host mount, Docker socket ve varsayılan olarak dışa internet erişimi yoktur.
- Zayıf TLS, varsayılan kimlik bilgileri ve açık servisler kasıtlıdır ve
  belgelenmiştir; başka hiçbir yerde kullanılmamalıdır.
- Tüm seed verileri sentetiktir.

Paylaşılan bir host'ta çalıştırmadan önce
[docs/tr/guvenlik.md](docs/tr/guvenlik.md) dosyasını okuyun.

---

## 9. Lisans

Copyright (C) 2026 Cuma KURT.

VulnForge Lab, **GNU Affero General Public License v3.0 yalnızca**
(`AGPL-3.0-only`) koşulları altında özgür yazılımdır. Tam metin için
[LICENSE](LICENSE) dosyasına bakın.

Bu uygulama ağ üzerinden erişilebilir olduğundan AGPL, ağ üzerinden etkileşen
kullanıcılara ilgili kaynak kodun sunulmasını gerektirir. Değiştirilmiş bir
sürümü yayınlarsanız değişikliklerinizi aynı lisansla yayınlamalısınız.

Bu program faydalı olması umuduyla dağıtılmaktadır, ancak **hiçbir garanti
verilmez**; satılabilirlik veya belirli bir amaca uygunluk garantisi dahi
verilmez.

---

## 10. Geliştirici

**Cuma KURT**

- E-posta: <cumakurt@gmail.com>
- LinkedIn: <https://www.linkedin.com/in/cuma-kurt-34414917/>
- GitHub: <https://github.com/cumakurt/vulnforge>

Bu lab'ı yalnızca yetkili güvenlik testleri ve eğitim için kullanın. İçerdiği
teknikleri sahibi olmadığınız veya açık izin almadığınız sistemlerde asla
kullanmayın.
