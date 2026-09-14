# Contributing to SentinelScope

Thank you for helping improve SentinelScope. Keep changes focused, explain the security or analyst value, and avoid introducing offensive behavior or real sensitive data.

## Development workflow

1. Create a branch from `main`.
2. Add or update tests with the implementation.
3. Run the relevant quality gates locally.
4. Open a pull request that describes the problem, solution, validation, and security impact.

Backend checks:

```bash
cd backend
python -m pytest --cov=app --cov-report=term-missing --cov-fail-under=90
ruff check app tests scripts migrations
bandit -q -r app scripts ../examples
python -m scripts.evaluate_model
```

Frontend checks:

```bash
cd frontend
npm test
npm run build
```

Schema changes must include an Alembic revision and must be validated against a new database with `alembic upgrade head`.

## Pull request checklist

- [ ] The change has a clear, defensive use case.
- [ ] Tests cover success, failure, and security-sensitive boundaries.
- [ ] Documentation and example configuration match the implemented behavior.
- [ ] No credentials, tokens, personal data, generated databases, or build artifacts are committed.
- [ ] New detection claims identify their dataset and limitations.
- [ ] CI, linting, security scanning, and production build pass.

Security vulnerabilities should follow [SECURITY.md](SECURITY.md), not the public issue tracker.
