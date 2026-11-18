# Tarayıcı entegrasyonu

VulnForge tüm servisleri tek bir gateway üzerinden sunar:

```
http://127.0.0.1:8000/
```

Kök sayfa, işlemleri çalışan ShopForge mağazasıdır. Kurulum `--port 18000` ile
yapıldıysa `http://127.0.0.1:18000/` adresini kullanın. Mağaza gezintisinde
zafiyet adları, saldırı örnekleri, test hesapları veya lab tanılama bağlantıları
gösterilmez. Yalnızca `/` üzerinden başlayan tarama normal mağaza akışlarını
dolaşır; aşağıdaki bütün eski lab endpoint'lerini keşfetmesi beklenmez.
Katalog kapsamındaki tam ölçüm için [zafiyet kataloğundaki](zafiyet-katalogu.md)
yolları tarayıcıya başlangıç URL'leri olarak ayrıca verin.

Hesaplar, kalıcı veriler ve cookie tabanlı `/store-api/` endpoint'leri
[ShopForge rehberinde](../shopforge.md) açıklanır. ShopForge oturumu eski lab
servislerinde kimlik doğrulamaz.

| Önek | Servis | Ground-truth kapsamı |
|---|---|---|
| `/php/` | php-web | SQLi, XSS, CMDi, LFI, upload, CSRF, IDOR, auth |
| `/api/` | node-api | OWASP API Top 10 (BOLA, BOPLA, BFLA, JWT, NoSQLi, SSRF) |
| `/py/` | flask-svc | SSTI, deserialization, path traversal, SSRF, CMDi, ReDoS |
| `/java/` | spring-svc | XXE, XMLDecoder, EL injection, JNDI, zayıf kripto |
| `/go/` | go-svc | SSRF, race condition, iş mantığı, OTP brute force |
| `/graphql` | node-api | introspection, batching, alias DoS, BOLA |
| `/graphql_safe` | node-api | hardened ikiz (kontrol ölçümü) |
| `/spa/` | node-api | SPA yönlendirme, robots, source map, soft-404, SSE |
| `/legacy/` | flask-svc | eski bileşenler, yedek dosyalar, varsayılan parola |
| `/auth/` | flask-svc | OAuth/OIDC/SAML zafiyetleri |

`lab-control` `127.0.0.1:9100` üzerinde dinler ve tarayıcı kapsamı **dışındadır**.
Durumu sıfırlamak ve ölçüm oturumu başlatmak için kullanın:

```bash
curl -X POST http://127.0.0.1:9100/__lab/session/start \
     -H 'Content-Type: application/json' \
     -d '{"scanner_name":"my-scanner","scanner_version":"1.0"}'

# taramayı çalıştır

curl -X POST http://127.0.0.1:9100/__lab/session/stop
```

Durdurma yanıtı oturum sırasında gözlenen `triggered_vuln_ids` listesini verir.

## Ground-truth endpoint'leri

* `GET /__lab/vulns` — filtrelenmiş ground truth (mode'a saygı duyar)
* `GET /__lab/controls` — güvenli ikizler
* `GET /__lab/events` — `vuln_triggered` ve oturum olayları
* `POST /__lab/reset` — eski lab verileri ve olaylarını sıfırlar; ShopForge verileri korunur
* `POST /__lab/seed?profile=small|large` — veri hacmi
* `PUT /__lab/mode` — servis, OWASP kategorisi ve seviyeye göre kısıtla
* `PUT /__lab/waf` — WAF profili seç

## Önerilen akış

1. Lab'ı sıfırlayın.
2. Oturum başlatın.
3. Tarayıcıyı yalnızca gateway'e yönlendirin.
4. Oturumu durdurun ve `/__lab/events` çıktısını dışa aktarın.
5. Tarayıcı çıktısını skorlayın:

```bash
python3 scorer/scorer.py \
  --findings scanner.json \
  --truth-dir lab/truth \
  --events http://127.0.0.1:9100/__lab/events \
  --out-dir scorer/out
```

Lab sürümü, tarayıcı sürümü ve raporu birlikte saklayın; böylece sonuçlar
koşular arasında karşılaştırılabilir kalır.

## Kapsam dışı bırakılacak yollar

Tarayıcıya şu yolları kapsam dışı bırakın:

* `127.0.0.1:9100` (lab-control)
* `127.0.0.1:9000` (OOB collector)
* `/scan-fixtures/` (katalog skorlamasında; pasif örnekler katalog ID'si değildir)

Bunlar harness bileşenleridir ve taranmaları skoru bozar.

## Kimlik doğrulama ve pasif örnekler

Mağaza taramasında `/login` formunu gönderip oturum cookie'sini ve güncel CSRF
form alanlarını koruyun. Yönetici ve müşteri rollerini ayrı oturumlarda ölçün.
Eski PHP/Node/OAuth servisleri kendi oturum veya token'larını kullanır; bunlar
mağaza oturumundan bağımsızdır.

`/scan-fixtures` dizin sayfası 404 döndürür. Ham örnekleri doğrudan
`/scan-fixtures/{case}/{variant}` yolundan isteyin. `case` için
`version-header`, `error-detail`, `internal-hostname`; `variant` için
`sample-a`, `sample-b` kullanılabilir. Bu altı yanıtın beklenen sinyalleri
[ShopForge rehberinde](../shopforge.md#scanner-scope-and-findings) açıklanır;
mağazada örnekler listelenmez. Bunları katalog skorlamasından ayrı karşılaştırın.
