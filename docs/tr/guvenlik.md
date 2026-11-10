# Güvenlik modeli

VulnForge Lab **kasıtlı olarak zafiyetlidir**. Bu doküman, bu zafiyetin nasıl
kontrol altında tutulduğunu açıklar.

## Kapsam

* Lab'ı yalnızca sahibi olduğunuz veya açıkça test yetkisi aldığınız bir makinede
  kullanın.
* Yalnızca tarayıcı ölçümü, eğitim ve araştırma için kullanın.
* İnternete, kurumsal ağa veya güvenilmeyen ağlardan erişilebilen paylaşımlı bir
  CI runner'a asla açmayın.

## Ağ izolasyonu

| Kontrol | Uygulama |
|---|---|
| Loopback bağlama | Yayınlanan tüm portlar `${BIND_HOST:-127.0.0.1}` kullanır |
| Dahili uygulama ağı | `lab_net` (yalnızca gateway ↔ servisler) |
| Veritabanı ağı | `data_net` `internal: true`; tarayıcı erişemez |
| SSRF ağı | `internal_net` `internal: true`; metadata simülatörünü barındırır |
| Açık servisler | `exposed_net` yalnızca kasıtlı açık servisleri taşır (Redis vb.) |
| Dışa internet | Varsayılan kapalı; açmak için `ALLOW_EGRESS=true` gerekir |

## Konteyner sertleştirmesi

* Her serviste `security_opt: no-new-privileges:true`.
* `deploy.resources.limits` ile CPU ve bellek limitleri.
* Ortak anchor üzerinde `pids` limitleri.
* `--privileged` yok, host network yok, uygulama kodu için host bind mount yok.
* Docker socket hiçbir konteynere bağlanmaz.

## Kasıtlı zafiyetler ve koruma önlemleri

| Zafiyet | Koruma |
|---|---|
| Command injection, SSTI, deserialization ile RCE | Komutlar zararsız (`id`, `echo`, `sleep`); host mount yok; konteyner kapsamlı |
| SSRF | Yalnızca `internal_net` ve sahte metadata servisine ulaşır; egress kapalı |
| Log4Shell benzeri JNDI | Yalnızca out-of-band HTTP callback; sınıf yükleme ve gerçek LDAP yok |
| Dizin listeleme / yedek / `.git` açığı | Yalnızca sentetik dosyalar; gerçek kaynak veya kimlik bilgisi yok |
| Varsayılan kimlik bilgileri | Sabit sentetik hesaplar; katalogda belgelenmiş |
| Zayıf TLS profilleri | Gateway imajı içinde üretilen self-signed sertifikalar |
| Kaynak tüketimi | Sınırlı payload boyutları; gerçek sınırsız DoS yok |

## Veri

* Tüm kayıtlar seed script'leriyle üretilir ve sentetiktir.
* Repository'de gerçek kişisel veri, parola, token, private key veya üretim
  bağlantı dizesi yoktur.
* Bulgularda görünen sırlar (örneğin JWT `secret`) kasıtlı yer tutuculardır ve
  asla yeniden kullanılmamalıdır.

## Bilinen sınırlamalar

* `data_net` ve `internal_net` Docker içinde izolasyon sağlar; ele geçirilmiş bir
  Docker host bu sınırı kaldırır. Lab'ı ayrı bir VM veya ayrı Docker daemon
  üzerinde çalıştırın.
* `legacy-svc` ve `auth-svc` banner ve metadata'ları simülasyondur; gerçek
  zafiyetli paketler değildir.
* Java katmanı, Maven indirmesi gerektirmeden deterministik derleme için Spring
  Boot yerine JDK HTTP sunucusu kullanır. Tarama açısından zafiyet semantiği
  eşdeğerdir.
* `node-api` NoSQL enjeksiyonu, bellek içi store üzerinde MongoDB operatör
  değerlendiricisi ile modellenmiştir; bu, veritabanı gidiş-dönüşü olmadan
  deterministik reset sağlar. `mongodb` konteyneri ileride kalıcılık ve port
  tarama senaryoları için veri katmanında kalır.

## Sorun bildirme

Lab harness'inde (kasıtlı zafiyet değil) bir hata bulursanız
<https://github.com/cumakurt/vulnforge/issues> adresinde issue açın veya Cuma
KURT <cumakurt@gmail.com> ile iletişime geçin.

Kasıtlı lab zafiyetlerini güvenlik açığı olarak bildirmeyin; tam liste
[zafiyet-katalogu.md](zafiyet-katalogu.md) içindedir.
