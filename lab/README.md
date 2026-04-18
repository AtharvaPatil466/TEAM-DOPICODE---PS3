# ShadowTrace Demo Lab

Four-container private-subnet lab used for the demo's internal-phase scan.

| Role | Container | IP | Notes |
|------|-----------|-----|-------|
| Entry point (exposed web) | shadowlab-apache | 172.28.0.10 | httpd 2.4.49 — CVE-2021-41773 |
| Crown jewel (database) | shadowlab-mysql | 172.28.0.20 | MySQL 5.7, weak creds |
| IoT device | shadowlab-iot | 172.28.0.30 | busybox httpd, no auth |
| Rogue laptop | shadowlab-rogue | 172.28.0.40 | sshd with PermitRootLogin |

## Run

```
cd project/lab
docker compose up -d
```

Scan from the host against `172.28.0.0/24`. The attack-path demo expects the
two-hop chain `apache-legacy → mysql-crown`.

## Reset

```
docker compose down -v
```
