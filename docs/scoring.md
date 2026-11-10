# Scoring

The scorer compares scanner findings with the generated ground truth and reports
precision, recall and F1. It is intentionally strict about safe twins: a finding
on a control endpoint is always a false positive, even if the same URL pattern
would match a vulnerable endpoint elsewhere.

## Finding schema

```json
{
  "findings": [
    {
      "url": "/php/sqli/products.php",
      "method": "GET",
      "parameter": "id",
      "cwe": "CWE-89",
      "type": "sqli",
      "evidence": "MySQL error containing version()"
    }
  ]
}
```

`url` may be absolute or relative. Paths are normalised (case preserved, trailing
slashes and empty segments removed) and the query string is ignored; the
`parameter` field carries the injection point.

## Matching rules

1. Exact URL path + method + parameter match.
2. The CWE must agree when the scanner supplies one; otherwise the free-form
   `type` is compared with the ground-truth `type`.
3. If the scanner omits the parameter, a URL + method match is accepted.
4. Findings that resolve to a control twin are counted as definite false
   positives.
5. Duplicate findings for an already detected vulnerability are ignored rather
   than inflating the false-positive count.

## Metrics

* `precision = TP / (TP + FP)`
* `recall = TP / (TP + FN)`
* `f1 = 2PR / (P + R)`
* `fp_rate = FP / (TP + FP)`
* Safe-twin FP rate is reported separately.

Breakdowns are produced for OWASP Web/API categories, CWE, service, difficulty
level and detection class.

## Exploit proof

When `--events` points to `lab-control` (`/__lab/events`) or a saved JSON file,
the scorer reports how many detected vulnerabilities also produced a
`vuln_triggered` event. This separates *reported* from *verified exploitation*.

## CI thresholds

```bash
python3 scorer/scorer.py --findings out.json \
  --fail-under recall=0.80 \
  --fail-over fp=0.05
```

The command exits `1` when a threshold is violated.
