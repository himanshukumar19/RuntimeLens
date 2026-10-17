# GLOSSARY

### Typed Decision Model
A constrained-output machine learning model that accepts structured text/JSON state and evaluates predefined typed questions in a single forward pass, returning calibrated probabilities and discrete choices rather than generating open-ended, free-form text.

### Choice Question
A typed question format defining a fixed set of discrete categorical options (with descriptive prompts). The model returns the chosen category alongside a probability distribution across all options and an overall confidence score.

### Score Question
A typed question format evaluating state against an ordered rubric or numerical scale (e.g., severity levels 1 to 5). The model returns an interpolated scalar score, level probabilities, and confidence.

### Noul Question
A typed binary verification question evaluating whether a specific factual or semantic claim is true. The model returns a single scalar probability ($p \in [0, 1]$) without a separate confidence field ($p \approx 0.5$ implies maximum uncertainty).

### Workload Baseline
A machine-readable specification of expected runtime, network, and orchestration behaviour for a specific containerized workload (e.g., allowed binaries, parent processes, expected network peers, permitted mounts), used to contextualize raw events.

### Deterministic Fact Extraction
Pre-processing logic in code that computes unambiguous boolean or categorical facts from raw telemetry (e.g., whether `/var/run/docker.sock` is mounted, whether the container is running as root) before passing state to the classifier.

### Pre-Filter
A lightweight, rule-based screening layer that immediately drops or routes routine, high-volume benign telemetry before invoking higher-latency, higher-cost ML or hosted decision endpoints.

### Dry-Run Quarantine
A non-disruptive response action where the containment policy engine generates the precise Kubernetes `NetworkPolicy` manifest needed to isolate a compromised pod and writes it to an audit log without actually applying it to the live cluster.

### Confidence Gate
A deterministic policy rule that evaluates the model's reported confidence and probability spread. If confidence falls below an established threshold, automated action is withheld, and the event is routed to human review.

### Grouped Split
A cross-validation dataset splitting technique that ensures all events belonging to the same synthetic scenario execution or cluster run ID remain entirely within either the tuning set or the held-out test set, preventing temporal or contextual data leakage.
