# Kurulum

VulnForge Lab bir Docker Compose stack'i olarak çalışır. Önerilen yol, eksik
paketleri tespit edip kurulumdan önce onay isteyen tek komutluk kurulum
script'idir.

## Gereksinimler

| Bileşen | Minimum | Not |
|---|---|---|
| Docker Engine | 20.10+ | Rootless veya sudo kullanılabilir |
| Docker Compose eklentisi | 2.20+ | `docker compose` (v2), `docker-compose` v1 değil |
| curl | herhangi | Health probe ve kurulum kontrolleri |
| python3 + pip | 3.10+ | Yalnızca smoke testleri ve scorer için |
| RAM | 2 GB (core) / 8 GB (full) | Full profil 18 konteyner çalıştırır |
| Disk | 6 GB | Base imajlar ve build cache |

## Otomatik kurulum

```bash
./docker_install.sh                  # core: gateway, php-web, mysql, lab-control
./docker_install.sh --profile full   # tüm servisler
```

Script şu adımları uygular:

1. İşletim sistemini ve paket yöneticisini tespit eder (`apt`, `dnf`, `yum`,
   `pacman`, `zypper`, `apk`, `brew`).
2. Docker, Compose eklentisi, curl ve python3 durumunu kontrol eder.
3. Eksik varsa paket listesini yazdırır ve paket yöneticisini çalıştırmadan
   **önce onay ister**.
4. Docker kurulu ama durmuşsa (onayla) servisi başlatır.
5. Gerektiğinde `.env` dosyasını `.env.example` üzerinden oluşturur.
6. Boş bir host portu seçer; `8000` genellikle başka bir konteyner tarafından
   kullanıldığı için `18000`, `18080`, `28000`, `38000` sırayla denenir.
7. Seçilen profili derler ve başlatır.
8. `lab-control` ve gateway sağlıklı olana kadar bekler.
9. `python3-requests` varsa smoke testlerini çalıştırır.
10. Tüm erişim adreslerini, demo kimlik bilgilerini ve faydalı `make`
    komutlarını yazdırır.

### Parametreler

```
--profile <core|full|api|infra|waf|crawl>
--port <port>            gateway HTTP portu
--https-port <port>      gateway HTTPS portu
--lab-port <port>        lab-control portu
--yes                    hiç soru sorma (CI)
--skip-build             mevcut imajları kullan
--skip-tests             smoke testlerini çalıştırma
--help
```

### Sorusuz örnek

```bash
./docker_install.sh --profile full --port 18000 --yes --skip-tests
```

## Manuel kurulum

```bash
cp .env.example .env
docker compose --profile full up -d --build
curl -X POST http://127.0.0.1:9100/__lab/reset
```

Sağlık kontrolü:

```bash
docker compose --profile full ps
curl -s http://127.0.0.1:9100/__lab/health | python3 -m json.tool
```

## Profiller

| Profil | Servisler |
|---|---|
| `core` | gateway, php-web, mysql, lab-control |
| `full` | tüm servisler, altyapı ve lab araçları |
| `api` | API odaklı alt küme (node-api, flask-svc, graphql-svc, mongodb, postgres) |
| `infra` | açık altyapı (redis, mailhog, OOB collector, metadata) |
| `waf` | gateway ve WAF/TLS profil çalışmaları |
| `crawl` | crawl-lab ve gateway |

## Yapılandırma

`.env.example` dosyasını `.env` olarak kopyalayıp düzenleyin:

| Değişken | Varsayılan | Amaç |
|---|---|---|
| `BIND_HOST` | `127.0.0.1` | Yayınlanan portların host arayüzü |
| `GATEWAY_HTTP_PORT` | `8000` | Gateway HTTP portu |
| `GATEWAY_HTTPS_PORT` | `8443` | Gateway HTTPS portu |
| `LAB_CONTROL_PORT` | `9100` | lab-control portu |
| `WAF_PROFILE` | `waf-off` | WAF profil adı |
| `SEED_PROFILE` | `small` | `small` veya `large` seed verisi |
| `ALLOW_EGRESS` | `false` | SSRF hedeflerinin dışa internet erişimi |

Paylaşılan veya internete açık bir host'ta `BIND_HOST=0.0.0.0` ayarlamayın.

## Doğrulama

```bash
pip install -r tests/requirements.txt
make smoke      # 99 kontrol: her zafiyet sömürülebilir
make controls   # 99 kontrol: her güvenli ikiz payload'ı reddeder
make test       # ikisi birlikte
```

## Sorun giderme

### Port zaten kullanımda

Genellikle Portainer `8000` portunu kullanır. `--port 18000` verin veya script'in
boş portu otomatik seçmesine izin verin.

### `docker compose` bulunamadı

Compose v2 eklentisini kurun. Eski `docker-compose` v1 desteklenmez.

### Bir servis sağlıklı olmuyor

```bash
docker compose --profile full logs <servis>
docker compose --profile full ps
```

`lab-control` hangi servisin kapalı olduğunu raporlar:

```bash
curl -s http://127.0.0.1:9100/__lab/health | python3 -m json.tool
```

### Core profilde SSRF testleri başarısız

`internal-metadata`, `oob-collector` ve Go/Flask SSRF hedefleri `full` profiline
aittir. Tam test seti için `./docker_install.sh --profile full` kullanın.

### Docker socket izin hatası

Kullanıcıyı `docker` grubuna ekleyip yeniden oturum açın veya kurulum script'ini
`sudo` ile çalıştırın.
