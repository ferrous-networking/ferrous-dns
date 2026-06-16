# Integrations

Ferrous DNS is built around a fully documented REST API, so any tool that speaks HTTP and understands [OpenAPI](https://www.openapis.org/) can drive it. This page covers the built-in interactive API explorer (Swagger-style docs) and how to plug the OpenAPI specification into external tooling.

---

## Interactive API Docs (Swagger / Scalar)

The server ships a built-in interactive API explorer rendered with [Scalar](https://scalar.com) — the same "try it in the browser" experience you get from Swagger UI. It is served on the web port (`web_port`, default `8080`) and requires **no authentication** to open.

| Mode | OpenAPI spec | Interactive docs |
|:-----|:-------------|:-----------------|
| Normal | `http://<server>:8080/api/openapi.json` | `http://<server>:8080/api/docs` |
| Pi-hole compat (native API) | `http://<server>:8080/ferrous/api/openapi.json` | `http://<server>:8080/ferrous/api/docs` |
| Pi-hole compat (Pi-hole API) | `http://<server>:8080/api/openapi.json` | `http://<server>:8080/api/docs` |

!!! note "Scalar, not Swagger UI"
    The bundled UI is Scalar, which renders the same OpenAPI 3.x spec Swagger UI consumes. If you prefer Swagger UI specifically, point it at the `openapi.json` endpoint above — the spec is identical.

---

## Using the OpenAPI Spec

The spec describes every handler, request/response schema, parameter, and security scheme (`session_cookie` + `X-Api-Key` for the native API, `X-FTL-SID` for the Pi-hole layer). Feed it into any OpenAPI-aware tool:

=== "Swagger UI"
    ```bash
    docker run -p 8081:8080 \
      -e SWAGGER_JSON_URL=http://<server>:8080/api/openapi.json \
      swaggerapi/swagger-ui
    ```

=== "Postman / Insomnia"
    Import the collection from the spec URL:
    ```text
    http://<server>:8080/api/openapi.json
    ```

=== "Generate a client"
    ```bash
    openapi-generator-cli generate \
      -i http://<server>:8080/api/openapi.json \
      -g python \
      -o ./ferrous-client
    ```

=== "Contract tests"
    ```bash
    schemathesis run http://<server>:8080/api/openapi.json \
      --header "X-Api-Key: your-token"
    ```

!!! tip "Authenticating from external tools"
    For programmatic access create an API token in the dashboard (or via the [API Token endpoints](api.md#api-tokens)) and send it in the `X-Api-Key` header. See [Authentication](api.md#authentication) for the full guard behaviour.

---

## Pi-hole v6 API

When `pihole_compat = true`, Ferrous DNS also exposes a Pi-hole v6 compatible API at `/api/*`, so existing Pi-hole clients, mobile apps, and dashboards work unchanged. The native Ferrous API moves to `/ferrous/api/*` in this mode.

See [Pi-hole Compatibility](features/pihole-compat.md) for the supported endpoints and behaviour.

---

## See Also

- [REST API Reference](api.md) — every endpoint with request/response examples
- [Pi-hole Compatibility](features/pihole-compat.md) — drop-in Pi-hole v6 API layer
- [Security](features/security.md) — auth, API tokens, and TLS for the API
