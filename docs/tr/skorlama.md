# Skorlama

Scorer, tarayıcı bulgularını üretilen ground truth ile karşılaştırır ve
precision/recall/F1 raporlar. Güvenli ikizler konusunda kasıtlı olarak katıdır:
kontrol endpoint'inde oluşan bir bulgu, aynı URL deseni başka yerde zafiyetli
olsa bile her zaman yanlış pozitiftir.

## Bulgu şeması

```json
{
  "findings": [
    {
      "url": "/php/sqli/products.php",
      "method": "GET",
      "parameter": "id",
      "cwe": "CWE-89",
      "type": "sqli",
      "evidence": "version() içeren MySQL hatası"
    }
  ]
}
```

`url` mutlak veya göreli olabilir. Yollar normalize edilir (büyük/küçük harf
korunur, sondaki eğik çizgi ve boş segmentler kaldırılır), query string yok
sayılır; enjeksiyon noktası `parameter` alanında taşınır.

## Eşleştirme kuralları

1. Tam URL yolu + metot + parametre eşleşmesi.
2. Tarayıcı CWE veriyorsa CWE uyuşmalıdır; vermiyorsa serbest `type` alanı
   ground-truth `type` değeriyle karşılaştırılır.
3. Tarayıcı parametre belirtmemişse URL + metot eşleşmesi kabul edilir.
4. Kontrol ikizine düşen bulgular kesin yanlış pozitif sayılır.
5. Zaten tespit edilmiş bir zafiyet için tekrar eden bulgular yanlış pozitif
   sayısını şişirmemek için yok sayılır.

## Metrikler

* `precision = TP / (TP + FP)`
* `recall = TP / (TP + FN)`
* `f1 = 2PR / (P + R)`
* `fp_rate = FP / (TP + FP)`
* Güvenli ikiz yanlış pozitif oranı ayrıca raporlanır.

Kırılımlar: OWASP Web/API kategorisi, CWE, servis, zorluk seviyesi ve tespit
sınıfı.

## Sömürü kanıtı

`--events` parametresi `lab-control` (`/__lab/events`) veya kaydedilmiş bir JSON
dosyasını gösterdiğinde, scorer tespit edilen zafiyetlerden kaçının aynı zamanda
`vuln_triggered` olayı ürettiğini raporlar. Bu, *raporlanan* ile *doğrulanmış
sömürü* ayrımını sağlar.

## CI eşikleri

```bash
python3 scorer/scorer.py --findings out.json \
  --fail-under recall=0.80 \
  --fail-over fp=0.05
```

Eşik ihlalinde komut `1` koduyla çıkar.

## Adapter'lar

| Adapter | Girdi |
|---|---|
| `custom_json` | `{"findings": [...]}` veya düz liste |
| `sarif` | SARIF 2.1.0 |
| `zap` | ZAP JSON raporu |
| `nuclei` | Nuclei JSONL |

## Çıktılar

`scorer/out/` altında:

* `report.json` — tüm metrikler, kırılımlar, kaçırılanlar, yanlış pozitifler
* `report.csv` — zafiyet bazında tespit/sömürü tablosu
* `report.html` — grafik kartları, kırılım tabloları, kaçırılan zafiyetler
