# portal-ucas-ac-cn

Headless sign-in for the UCAS (Srun) campus network portal at
<https://portal.ucas.ac.cn>. Pure Python standard library, no runtime
dependencies.

## Install

```sh
uv tool install .
# or, from a checkout
uv run ucas-portal
```

## Usage

```sh
ucas-portal
# or
python -m portal_ucas_ac_cn
```

The command prompts for your email, password, and the server IP (auto-detected
from the local interfaces, with the portal's own view as a fallback), then
prints the portal's JSON response.

The portal binds a session to the IP it sees, so an explicit `Server IP` lets
you sign in on behalf of another device.

## Development

```sh
uv sync          # create .venv and install the project + dev group
uv run pytest
uv run ruff check .
uv run ruff format .
```

## License

MIT
