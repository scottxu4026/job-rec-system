## Repository layout
- web-app: React + Vite frontend (dev: 5174)
- web-bff: Spring Cloud Gateway (dev: 8080)
- services/user-service: Spring Boot user service (dev: 8081)
- services/*: placeholders for future services
- libs, contracts, infra, docs, scripts: scaffolding

## Local Dev Topology
- Frontend: http://localhost:5174 (always calls `/api/**`)
- Gateway: http://localhost:8080 (routes `/api/users/**` → user-service)
- User-service: http://localhost:8081
- Postgres (dev): localhost:5433

## Quickstart
1) User-service (8081)
```bash
cd services/user-service
./mvnw spring-boot:run
```
2) Gateway (8080)
```bash
mvn -q -f web-bff/pom.xml spring-boot:run
```
3) Frontend (5174)
```bash
cd web-app
npm run dev
```

## Verify path forwarding
```bash
curl -i http://localhost:8080/api/users/ping
```
Expected: response from user-service, with `/api` stripped by the gateway.
