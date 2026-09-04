# Caddy remote_host matcher

## Build

```sh
xcaddy build --with github.com/mikucat0309/caddy-remote-host
```

## Usage

```
@allowlist remote_host allowlist.example.org
respond @allowlist 200
respond 404
```
