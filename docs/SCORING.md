# Risk prioritisation: formula, weights, limitations

The platform computes an **internal priority score (0-100)**. It is **not a CVSS score**, not an official rating, and is never labelled as one.
CVSS severity (from the scanner) and internal priority are always shown separately.

## Inputs (nothing is invented)
| Component | Normalised value | Treated as *missing* when |
|---|---|---|
| `cvss` | score / 10 | source is "Heuristic estimate (not CVSS)" or "None". The old parser's port-based guesses are labelled and excluded. |
| `criticality` (asset) | Critical 1.0, High .75, Medium .5, Low .25 | `Unrated` |
| `exposure` (asset) | Internet-facing 1.0, Internal .3 | `Unknown`. Setting a value requires a stated source. |
| `exploit` | Known exploited (KEV match) 1.0, Exploit confirmed (evidence) 1.0, Public exploit reference .7, None known 0 | `Unknown`. A *lack* of KEV match is **not** evidence of safety. |
| `sla` | 1.0 if overdue, else elapsed fraction of the SLA window | finding closed / no deadline |
| `business` (asset) | Mission-critical 1.0, Important .6, Supporting .3 | `Unrated` |

## Formula
```
score = 100 * sum(w_i * n_i  for known i) / sum(w_i for known i)
confidence_ratio = sum(w_i for known i) / sum(all w_i)
```
Default weights (editable by admins, audited): cvss .40, criticality .20, exposure .15, exploit .15, sla .05, business .05.
Categories: Critical >= 75, High >= 55, Medium >= 35, Low < 35.
Confidence: High >= 85% of weight known, Medium >= 60%, else Low.

* **CVSS missing -> category `Incomplete`**; the score shown is provisional and flagged.
* **Floor rule:** confirmed exploitation (KEV or analyst evidence) with CVSS >= 7 is never rated below High.
* Output also includes: factors that raised risk, missing evidence list, component values, and a recommended next action.
* Asset overall risk = top finding score + 0.5 x the next three, capped at 100 (a damped aggregate, documented heuristic).

## Limitations
* Weights are expert-chosen defaults, **not empirically calibrated or validated** against breach data.
* Renormalising over known inputs means two findings with different evidence coverage are not strictly comparable; use the confidence indicator.
* "Scanner-reported CVSS" is not independently verified against NVD (no live lookups are made). KEV data exists only if an admin imports the official catalogue.
* Exposure and criticality are only as good as what analysts record.
* No probability/EPSS modelling, no reachability analysis. The SLA forecast is rule-based, not predictive.
