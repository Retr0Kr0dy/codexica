# Codexica — Secure Manifest-Based File Browser

Codexica is a **read-only, manifest-driven file browser / downloader** designed to be exposed safely over the internet (Cloudflare tunnel, reverse proxy, etc.) while keeping **strict server-side access control**.

Authentication is handled by **Apache (BasicAuth)**.  
Authorization (what a user can see/download) is handled **inside the app**, based on **per-user manifests**.

This avoids:
- exposing the filesystem directly
- multiplying Apache virtual hosts
- trusting anything coming from the client

## Security Model (High Level)

- **AuthN**: Apache BasicAuth  
- **AuthZ**: PHP (`REMOTE_USER` → ACL → allowed manifests)
- **Data**: never exposed directly by Apache
- **Client**: sends only opaque UUIDs, never paths

Even if a user forges HTTP requests, they **cannot access files outside their allowed manifests**.

## Minimal Apache VirtualHost (recommended)

This setup matches a **Cloudflare tunnel → loopback Apache** architecture.

Apache only listens on loopback, authentication is enforced globally.

```apache
Listen 127.0.0.1:8443

<VirtualHost 127.0.0.1:8443>
  ServerName codexica.local
  DocumentRoot /var/www/codexica/www

  <Directory /var/www/codexica/www>
    AllowOverride None
    Require all granted
  </Directory>

  # Authentication (AuthN)
  <Location "/">
    AuthType Basic
    AuthName "Codexica"
    AuthUserFile /etc/apache2/codexica.htpasswd
    Require valid-user
  </Location>

  Header always set X-Content-Type-Options "nosniff"
</VirtualHost>
```

> Cloudflare tunnel connects to `127.0.0.1:8443`.
> Direct IP access is blocked by design (iptables / no public listener).

## Required Files & Directories

### 1) Authentication file (Apache)

**Path**

```
/etc/apache2/codexica.htpasswd
```

**Create**

```bash
htpasswd -c /etc/apache2/codexica.htpasswd user1
htpasswd    /etc/apache2/codexica.htpasswd user2
```

**Permissions**

```bash
chown root:www-data /etc/apache2/codexica.htpasswd
chmod 0640 /etc/apache2/codexica.htpasswd
```

### 2) ACL configuration (Authorization)

**Path**

```
/etc/codexica/acl.json
```

**Example**

```json
{
  "manifests": {
    "public": "/srv/codexica/manifests/public.json",
    "team":   "/srv/codexica/manifests/team.json",
    "full":   "/srv/codexica/manifests/full.json"
  },
  "users": {
    "user1": ["public"],
    "user2": ["public", "team"],
    "admin": ["full"]
  },
  "default": ["public"]
}
```

**Permissions**

```bash
mkdir -p /etc/codexica
chown root:www-data /etc/codexica
chmod 0750 /etc/codexica

chown root:www-data /etc/codexica/acl.json
chmod 0640 /etc/codexica/acl.json
```

> This file maps **Apache users → allowed manifest buckets**.

### 3) Manifest storage (outside webroot)

**Directory**

```
/srv/codexica/manifests/
```

**Permissions**

```bash
mkdir -p /srv/codexica/manifests
chown -R root:www-data /srv/codexica
chmod 0750 /srv/codexica
chmod 0750 /srv/codexica/manifests
```

Apache/PHP must be able to **read** manifests, nothing else.

### 4) Private data root (never exposed)

**Example**

```
/srv/data/
```

Rules:

* **NOT** under Apache `DocumentRoot`
* **NO** Apache `Alias`
* Accessed only by `downloader.php` after ACL checks

## Manifest Generation (Build Routine)

Manifests are **static JSON files** listing allowed files/directories.
They act as **whitelists**.

### Typical build script usage

Example (pseudo-CLI):

```bash
./build-manifest.sh \
  --root /srv/data \
  --whitelist /srv/data/public \
  --output /srv/codexica/manifests/public.json
```

Another one:

```bash
./build-manifest.sh \
  --root /srv/data \
  --whitelist /srv/data/team \
  --output /srv/codexica/manifests/team.json
```

And full access:

```bash
./build-manifest.sh \
  --root /srv/data \
  --output /srv/codexica/manifests/full.json
```

### Rules

* A manifest may only reference paths **under `/srv/data`**
* Each file gets a **UUID** (client never sees paths)
* Manifests are **read-only at runtime**

## Runtime Flow

1. User authenticates via Apache BasicAuth
2. Apache sets `REMOTE_USER`
3. `/manifest.php`

   * reads `/etc/codexica/acl.json`
   * resolves which manifests this user can access
   * merges entries
   * sends filtered manifest to client
4. `/downloader.php?q=<uuid>`

   * re-derives allowed manifests for the same user
   * checks UUID exists in those manifests
   * resolves real path
   * enforces `realpath ⊂ /srv/data`
   * streams file

No client-side parameter can override this.

## Security Notes

* `REMOTE_USER` is trusted because:

  * Apache performs the auth
  * origin is loopback-only
  * Cloudflare tunnel is the only ingress
* Forged requests cannot escape the ACL
* UUID guessing returns **404**, not authorization leaks
* Filesystem traversal and symlink escape are blocked
