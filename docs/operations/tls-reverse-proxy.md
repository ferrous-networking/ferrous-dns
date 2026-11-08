# TLS & Reverse Proxy

## Which certificate goes where

| Listener | Port | Certificate | Renewed by |
|:---------|:-----|:------------|:-----------|
| Dashboard, Ferrous API, Pi-hole API, DoH | web port (8080) | Towards clients, the reverse proxy's public certificate. Between the proxy and Ferrous DNS, the server's own self-signed one | The proxy, through ACME. The self-signed one, once a year by hand |
| DoT, DoQ | 853 | Files on disk: `[server.encrypted_dns] tls_cert_path` and `tls_key_path` | certbot and the [deploy hook](#dot-and-doq) |

The server reads certificates once, at startup. A new certificate on disk, an upload or a generated one takes effect after a restart, and a restart starts with an empty cache (see [Sizing](sizing.md#restarts)). In testing, DoT answered with the renewed certificate 0.4–0.5 s after the restart.

---

## Dashboard behind a reverse proxy

The proxy ends the public HTTPS connection and talks HTTPS to Ferrous DNS too. That second hop matters. The session cookie is marked `Secure` only when the server itself serves HTTPS, never because a proxy says so in `X-Forwarded-Proto`. Over plain HTTP behind the proxy, the browser would get a session cookie it is allowed to send in the clear.

### 1. Turn on HTTPS in Ferrous DNS

In **Settings → Security**, generate a self-signed certificate. `POST /ferrous/api/v1/tls/generate` does the same through the API. Then turn web TLS on and restart:

```toml
[server.web_tls]
enabled = true
```

The generated certificate is issued to `localhost` and `ferrous-dns`, and is valid for one year. **Settings → Security** shows when it expires, and every dashboard page shows a warning once the certificate the server is serving has less than 21 days left. Before then, generate a new one, restart, and refresh the proxy's copy (step 2). DoT and DoQ certificates in files of their own have no dashboard warning: rely on the alert rule for them.

### 2. Give the proxy a copy of the certificate

The proxies below check the server against its own certificate instead of turning verification off. Copy the certificate only, never the key:

=== "systemd"

    ```bash
    sudo install -m 0644 /var/lib/ferrous-dns/tls/cert.pem /etc/nginx/ferrous-dns-upstream.pem
    ```

    Or `/etc/caddy/` or `/etc/traefik/`, to match the proxy.

=== "Docker"

    ```bash
    docker cp ferrous-dns:/data/cert.pem ./ferrous-dns-upstream.pem
    ```

### 3. Configure the proxy

Replace `dns.example.com` with your host name. The examples reach Ferrous DNS at `127.0.0.1:8080`, with the proxy on the same host. With both in containers on one Docker network (see step 4), use the container's name instead: `https://ferrous-dns:8080`. The certificate names `ferrous-dns` too, so the check still matches.

=== "nginx"

    The public certificate comes from certbot (`certbot --nginx -d dns.example.com`). Install as `/etc/nginx/conf.d/ferrous-dns.conf`:

    ```nginx
    --8<-- "contrib/reverse-proxy/nginx.conf"
    ```

=== "Caddy"

    Caddy obtains and renews the public certificate itself:

    ```caddy
    --8<-- "contrib/reverse-proxy/Caddyfile"
    ```

=== "Traefik"

    The static configuration, `/etc/traefik/traefik.yml`:

    ```yaml
    --8<-- "contrib/reverse-proxy/traefik.yml"
    ```

    The routes, `/etc/traefik/traefik-dynamic.yml`:

    ```yaml
    --8<-- "contrib/reverse-proxy/traefik-dynamic.yml"
    ```

The proxy serves the whole site at the root of its own host name. The dashboard uses absolute paths, so it cannot live under a sub-path such as `/ferrous/`. Through that one host name it serves:

- the dashboard at `/`;
- the Ferrous API at `/ferrous/api/v1`;
- the [Pi-hole compatible API](../features/pihole-compat.md) at `/api`;
- DoH at `/dns-query`, once `[server.encrypted_dns] doh_enabled = true` (it is off by default);
- `/metrics`, if enabled.

The dashboard polls with plain requests, so no WebSocket settings are needed.

The server sends no security headers of its own. The examples add HSTS, `nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: same-origin`, all of which the dashboard works with. They add no Content-Security-Policy, which the dashboard has not been tested under.

### 4. Keep the dashboard port off the network

With a proxy in front, clients have no reason to reach port 8080 directly. The web port shares `[server] bind_address` with DNS, so binding it to loopback alone would take DNS off the network too. Close it in the firewall instead.

=== "Bare metal"

    Load this with `nft -f`, or add it to your nftables configuration. Port 53 stays open. Add an `accept` line, before the `drop`, for every other host that must reach the port, such as the Prometheus that scrapes `/metrics`:

    ```nft
    # Keep the dashboard port to this host: the reverse proxy reaches it over loopback.
    table inet ferrous_dns {
    	chain input {
    		type filter hook input priority filter; policy accept;
    		ip saddr 192.168.1.20 tcp dport 8080 accept   # Prometheus
    		iifname != "lo" tcp dport 8080 drop
    	}
    }
    ```

=== "Docker"

    Publish only port 53, and put the proxy on the same Docker network, so that it alone reaches 8080. The bundled compose file uses host networking, which mDNS discovery needs. With host networking the port is on the host, so use the nftables rule there.

### 5. Let DoH name its clients

Behind a proxy, every DoH request arrives from the proxy's address. `[server] trusted_proxies` lists the peers whose `X-Forwarded-For` the server believes. It defaults to loopback, which covers a proxy on the same host. A proxy on another host or container has to be listed:

```toml
[server]
trusted_proxies = ["127.0.0.0/8", "::1/128", "192.168.1.5/32"]
```

Otherwise every DoH client is logged as the proxy and gets the proxy's group. See [DoH client identity](../configuration/server.md#doh-client-identity).

Three more effects of the proxy:

- **Login lockout.** The lockout counts failures per connecting address. Behind the proxy, every login shares the proxy's count, so a burst of wrong passwords locks everyone out for the lockout window. See [Login lockout](../features/security.md#login-lockout).
- **Passkeys.** A passkey is bound to the name the browser sees, which is now the proxy's. Set `[auth.webauthn] rp_id = "dns.example.com"` and `rp_origin = "https://dns.example.com"`.
- **`/metrics`.** The proxy also forwards `/metrics`, which has no authentication. Block it on the proxy if the proxy is reachable from outside the network your Prometheus scrapes from.

All three configurations were run in front of the server with web TLS on and its generated certificate checked, as shipped except for the host name, the public certificate and the server's address. Through each one:

- HTTP redirected to HTTPS, and the headers above came back;
- a browser login on a non-loopback name got an `HttpOnly; SameSite=Strict; Secure` session cookie and loaded the Query Log;
- the Pi-hole API answered;
- DoH queries were logged under the real client's address, not the proxy's.

`nginx -t` and `caddy validate` accept the files as they are in `contrib/`.

---

## Renewing certificates

`/metrics` exports when each certificate the server loaded expires, as `ferrousdns_tls_cert_not_after_seconds{listener="web"|"dot"|"doq"}`, and the [`FerrousDnsCertificateExpiring`](logs-monitoring.md#alert-rules) rule fires 21 days ahead. The value is the certificate loaded at start: one renewed on disk counts once the server has restarted.

### Dashboard and DoH

The proxy renews its public certificate by itself: Caddy and Traefik through ACME, nginx through certbot's timer. Ferrous DNS does not need a restart for that. Only the self-signed certificate between the proxy and the server has to be replaced, once a year (step 1 above), along with every copy of it: the proxy's, and Prometheus's [`ca_file`](logs-monitoring.md#metrics).

### DoT and DoQ

DoT and DoQ clients see the server's own certificate, so it has to be one they trust. Give it its own files, so that a renewal never replaces the certificate the proxy checks:

```toml
[server.encrypted_dns]
dot_enabled = true
tls_cert_path = "/var/lib/ferrous-dns/tls/dot-cert.pem"
tls_key_path  = "/var/lib/ferrous-dns/tls/dot-key.pem"
```

[`contrib/certbot/ferrous-dns-deploy-hook.sh`](https://github.com/ferrous-networking/ferrous-dns/blob/main/contrib/certbot/ferrous-dns-deploy-hook.sh) runs after the certificate is issued and after every renewal of it. It installs the certificate and the key under the service user, readable by it alone, creates their directory if needed, and restarts the server.

That restart is what moves the `dot` and `doq` series forward. certbot renews 30 days before expiry, so `FerrousDnsCertificateExpiring` firing on a certbot-managed certificate means the renewal or the hook failed.

Keep it out of `renewal-hooks/deploy/`: certbot runs the hooks there for every certificate on the host, so the renewal of another one, such as the proxy's, would overwrite the DoT files. Pass it with `--deploy-hook` instead, which certbot keeps with this certificate's renewal settings:

```bash
sudo install -m 0755 ferrous-dns-deploy-hook.sh /usr/local/sbin/ferrous-dns-deploy-hook
sudo certbot certonly --standalone -d dns.example.com \
  --deploy-hook /usr/local/sbin/ferrous-dns-deploy-hook
```

`--standalone` needs port 80 free. With a proxy holding port 80, use certbot's `--webroot` or `--nginx` instead. A resolver reachable only inside your network cannot pass an HTTP challenge: use a DNS challenge plugin for your DNS provider.

For Docker, edit the four settings at the top of the hook:

- `CERT` and `KEY` to the files in the `/data` directory as the host sees it. `docker volume inspect -f '{{ .Mountpoint }}' ferrous-data` prints it; Compose names the volume after the project, such as `ferrous-dns_ferrous-data`;
- `OWNER` to `1000:1000`;
- `RESTART` to `docker restart ferrous-dns`.

```sh
--8<-- "contrib/certbot/ferrous-dns-deploy-hook.sh"
```

The hook was tested against [Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's test CA. certbot issued a certificate and then force-renewed it. Each time the hook installed both files with the right owner and mode, and after the restart DoT served the new certificate.
