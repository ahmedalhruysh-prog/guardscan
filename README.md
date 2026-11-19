# GuardScan — Secrets & Infrastructure Security Scanner

GuardScan is a standalone, security-first scanner that detects:
- **Exposed Secrets** (API keys, passwords, private keys, tokens).
- **Insecure Infrastructure-as-Code configurations** (Dockerfile, Docker Compose, Kubernetes, Terraform).

## Status
**Phase 3.1:** Project skeleton and CLI foundation (in progress).

## Build & Run
```powershell
go build -o guardscan.exe .\cmd\guardscan\
.\guardscan.exe --help