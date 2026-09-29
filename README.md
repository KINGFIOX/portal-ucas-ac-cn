# portal-ucas-ac-cn

Headless sign-in for the UCAS (Srun) campus network portal at
<https://portal.ucas.ac.cn>. Pure Python standard library, no runtime
dependencies.

## How it works

The Srun portal binds a session to the IP passed as `ip`, so this tool can
sign in **on behalf of another device** from your own machine.

The critical, easy-to-miss detail is `ac_id` (the NAS id of the device's
subnet). The portal hands the session to the NAS named by `ac_id`; a session
created with any other id is listed as online (`rad_user_info` says `ok`) but
carries **zero traffic** and the device's gateway never opens — the device
stays offline even though the tool reported success.

Find the device's own `ac_id` from the device itself (BusyBox `wget` is
enough). It must be a **real GET** — the portal 404s HEAD requests here, so
`wget --spider` and `curl -I` do not work:

```sh
wget -S -O /dev/null --no-check-certificate \
  https://portal.ucas.ac.cn/index_1.html 2>&1 | grep -i location
# Location: .../srun_portal_pc?ac_id=<N>&theme=pro   ← N is the answer
# or, with curl:
curl -sk -o /dev/null -w '%{redirect_url}\n' https://portal.ucas.ac.cn/index_1.html
```

IPv6 needs no sign-in on this network — only the IPv4 side is authenticated.

## Install

```sh
uv tool install . --force
# or, from a checkout
uv run portal-ucas-ac-cn --status
```

## Usage

```sh
# inspect a session (no credentials needed); spots the wrong-NAS failure mode
uv run portal-ucas-ac-cn --status 10.211.196.59

# sign a device in (password via prompt or $UCAS_PORTAL_PASSWORD)
uv run portal-ucas-ac-cn --email you@mails.ucas.ac.cn \
    --ip 10.211.196.59 --ac-id 12 --fresh
```

Flags:

- `--ip` — device IPv4 to sign in (default: prompt, pre-filled with this
  machine's address)
- `--ac-id N` — NAS id of the **device's** subnet.
- `--fresh` — log out an existing session for the device before signing in
  (needed after a wrong-`ac_id` attempt left a zombie session)
- `--status [IP]` — show the portal's view of a session and exit

After a successful login the tool re-checks the session and prints a
verification snippet to run on the device (`wget -T 8 -O /dev/null
http://www.baidu.com && echo IPv4 OK`).

## Development

```sh
uv sync          # create .venv and install the project + dev group
uv run pytest
uv run ruff check .
uv run ruff format .
```

## License

MIT
