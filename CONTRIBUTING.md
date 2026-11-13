# Contributing

Thanks for your interest in SecureSDP.

1. Open an issue first for anything larger than a small fix, so the design can be discussed.
2. Keep the code dependency-light (standard library first) and covered by tests.
3. Before opening a pull request, run:

   ```bash
   gofmt -l .            # must print nothing
   go vet ./...
   go test -race ./...
   docker compose up -d --build --wait && ./scripts/demo.sh   # if you touched the controller, AH, client or lab
   ```

4. Update the documentation in `docs/` when behaviour or configuration changes (`mkdocs build --strict` with `requirements-docs.txt`).
5. Do not commit keys, certificates or real credentials.

Security issues: see [SECURITY.md](SECURITY.md).
