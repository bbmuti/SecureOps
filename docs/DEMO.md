# 90-Second Demo Script

This short flow follows one event from ingestion to alert review and status change.

## Preparation

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:5173` and sign in with the analyst credentials configured in `.env`.

## Recording flow

1. **Overview — 10 seconds**
   Show the event, active-alert, critical-alert, and average-risk metrics. Explain that only active findings affect the security posture.

2. **Real ingestion — 15 seconds**
   Open Detection Lab and point to the JSON/JSONL, Linux OpenSSH, and Windows Security Event Log collectors.

3. **Controlled detection — 20 seconds**
   Run the brute-force scenario. Explain that these are safe application records processed by the same application path as collector events.

4. **Explainability — 20 seconds**
   Open the new alert. Show risk, evidence, MITRE ATT&CK context, model/rule reasoning, and the status selector.

5. **Analyst workflow — 15 seconds**
   Change the finding to `investigating`, then `resolved`. Open Audit Trail and show the recorded status change.

6. **Engineering proof — 10 seconds**
   End on the README quality-gate section: coverage, dependency audits, PostgreSQL smoke test, Windows collector validation, container builds, Bandit, Ruff, and Alembic migration.

## One-sentence pitch

> SentinelScope turns authentication and API telemetry into explainable, MITRE-mapped findings by combining deterministic rules with adaptive Isolation Forest behavior scoring.

Do not describe the synthetic smoke evaluation as real-world model accuracy. Refer to `BENCHMARKING.md` when discussing external data.
