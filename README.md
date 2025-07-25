# 🔐 OAuth2 WebFlux Authorization Server

This project demonstrates a **Spring Boot 3.2** based **OAuth2 Authorization Server and Resource Server** using **Spring Security**, **Spring WebFlux**, and **custom token introspection**. It includes role-based access (`USER`, `ADMIN`) and opaque token verification for secured endpoints.

---

## 📦 Technologies

- ✅ Java 17
- ✅ Spring Boot 3.2.x
- ✅ Spring Security (Reactive)
- ✅ Spring WebFlux
- ✅ Spring Authorization Server (Opaque tokens)
- ✅ Reactive OAuth2 Resource Server
- ✅ Role-Based Access with `@PreAuthorize`

---

## 🚀 Features

- 🛡️ OAuth2 Authorization Server with opaque token support
- 🔍 Custom token introspection endpoint
- ✅ Admin/User role-based access
- ⚡ Fully reactive with WebFlux
- 🧪 Secure token exchange with `/token` and `/introspect`
- 🗂️ Extensible for DB-based authentication

## 🧪 API Endpoints

| Method | Endpoint                   | Auth Required | Role    | Description                     |
|--------|----------------------------|----------------|---------|---------------------------------|
| POST   | `/custom-auth/token`       | ❌             | -       | Generate access token           |
| POST   | `/custom-auth/introspect`  | ❌             | -       | Token introspection (for resource server) |
| GET    | `/api/user/dashboard`      | ✅             | `USER`  | Accessible to USER role         |
| GET    | `/api/admin/dashboard`     | ✅             | `ADMIN` | Accessible to ADMIN role        |

---

## 🔐 Sample Roles

- 👤 `user` with password `user`
- 👑 `admin` with password `admin`

Default users are defined in the in-memory configuration. You can later extend this with a DB-based approach (see below).

---

## ⚙️ How to Run

### 🧬 Prerequisites

- Java 17
- Maven 3.8+

### 🏃 Run the App

```bash
# Clone the repo
git clone https://github.com/your-username/oauth2-webflux.git
cd oauth2-webflux

# Run the app
./mvnw spring-boot:run

