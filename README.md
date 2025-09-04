
## Repository layout
```
job-rec-system/
├─ web-app/
├─ web-bff/
├─ services/
│  ├─ user-service/
│  ├─ resume-service/
│  ├─ job-service/
│  ├─ rec-service/
│  ├─ behavior-service/
│  └─ notification-service/
├─ libs/
│  ├─ common-observability/
│  └─ common-security/
├─ contracts/
├─ infra/
│  ├─ dev-stack/
│  └─ k8s/
├─ docs/
├─ scripts/
```

### Quickstart
- Frontend dev: `cd web-app && npm run dev`
- Backend dev (user-service): `cd services/user-service && ./mvnw spring-boot:run`
- BFF: `web-bff/` placeholder; will route `/api/**` in future.
