# Live typed-decision evaluation — statistical summary

## groq-20b  (`openai/gpt-oss-20b`)

- incidents: 28 paired, 56 live calls, 0 failed calls
- macro-F1 with baseline: 0.7151  without: 0.7899
- delta macro-F1: -0.0747 (95% CI [-0.3096, +0.1436], p=0.5582)
- delta benign FPR: +0.0000 (95% CI [+0.0000, +0.0000], p=1.0000)
- delta accuracy: +0.0000
- mid-p McNemar on item correctness: b=3 c=3 p=1.0000
- per-class McNemar (Holm adjusted): container_escape=1.0000, privilege_abuse=1.0000, cryptomining=1.0000, unknown=1.0000, benign=1.0000
- attacks misread as benign: 1 with baseline vs 3 without (of 17 attacks)
- precision@K: @5=1.000, @10=0.900, @25=0.800, @50=0.786
- FPR at TPR: tpr0.9=0.000, tpr0.95=0.000
- latency ms: median 897.35, mean 1163, max 4579

### per-class F1 (with baseline)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.917 | 1.000 | 0.957 | 11 |
| container_escape | 0.500 | 0.200 | 0.286 | 5 |
| privilege_abuse | 0.556 | 0.833 | 0.667 | 6 |
| cryptomining | 1.000 | 1.000 | 1.000 | 4 |
| unknown | 1.000 | 0.500 | 0.667 | 2 |

## groq-qwen27b  (`qwen/qwen3.8-27b`)

- incidents: 28 paired, 56 live calls, 0 failed calls
- macro-F1 with baseline: 0.4802  without: 0.4828
- delta macro-F1: -0.0026 (95% CI [-0.1776, +0.2301], p=0.9920)
- delta benign FPR: -0.2727 (95% CI [-0.5714, +0.0000], p=0.0840)
- delta accuracy: +0.1071
- mid-p McNemar on item correctness: b=6 c=3 p=0.3438
- per-class McNemar (Holm adjusted): benign=0.6250, cryptomining=1.0000, container_escape=1.0000, unknown=1.0000, privilege_abuse=1.0000
- attacks misread as benign: 1 with baseline vs 1 without (of 17 attacks)
- precision@K: @5=1.000, @10=1.000, @25=0.680, @50=0.643
- FPR at TPR: tpr0.9=0.000, tpr0.95=0.000
- latency ms: median 405.15, mean 470, max 1483

### per-class F1 (with baseline)

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.917 | 1.000 | 0.957 | 11 |
| container_escape | 0.667 | 0.400 | 0.500 | 5 |
| privilege_abuse | 0.500 | 0.500 | 0.500 | 6 |
| cryptomining | 0.000 | 0.000 | 0.000 | 4 |
| unknown | 0.286 | 1.000 | 0.444 | 2 |
