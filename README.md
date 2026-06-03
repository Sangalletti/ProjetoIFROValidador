# Authos

Authos e um app Flask em arquivo unico para gerar QR Codes unicos, salvar o hash SHA-256 do token no SQLite e validar o QR em uma pagina publica com nome e CPF.

## Rodando localmente

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Configure as variaveis quando necessario:

```powershell
$env:BASE_URL='https://127.0.0.1:5443'
$env:SESSION_COOKIE_SECURE='true'
$env:SECRET_KEY='local-dev-secret-change-me'
```

Inicialize o banco, crie o admin e rode:

```powershell
flask --app app init-db
flask --app app create-admin admin
flask --app app run --host 127.0.0.1 --port 5443 --cert=adhoc
```

Para abrir pelo celular na rede local, use o IP do computador em `BASE_URL` e rode em todas as interfaces:

```powershell
$env:BASE_URL='https://SEU-IP:5443'
flask --app app run --host 0.0.0.0 --port 5443 --cert=adhoc --no-reload
```

## VPS

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export BASE_URL='https://seu-dominio.com'
export SECRET_KEY='troque-esta-chave'
flask --app app init-db
flask --app app create-admin admin
gunicorn --bind 127.0.0.1:8000 --workers 1 --threads 4 'app:app'
```

Coloque Caddy ou Nginx na frente do Gunicorn para fazer HTTPS e proxy para `127.0.0.1:8000`.

## Arquivos

- `app.py`: aplicacao, modelos, rotas, templates e CSS.
- `requirements.txt`: dependencias.
- `instance/authos.sqlite3`: banco local com registros e PNGs gerados.

## Seguranca

- O QR Code contem um token aleatorio em uma URL publica.
- O banco guarda o SHA-256 do token, nao o token bruto.
- O PNG gerado tambem pode ficar salvo no banco para permitir download depois.
- A senha do admin usa o hash seguro do Werkzeug.
- Em producao, use `SESSION_COOKIE_SECURE=true`, `SECRET_KEY` forte e `BASE_URL` com `https://`.
