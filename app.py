import hashlib
import os
import re
import secrets
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import click
import qrcode
from dotenv import load_dotenv
from flask import (
    Blueprint,
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.csrf import CSRFError
from jinja2 import DictLoader
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PREFERRED_URL_SCHEME = "https"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_TIME_LIMIT = None


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
public_bp = Blueprint("public", __name__)
CPF_DIGITS = re.compile(r"\D+")
TOKEN_SESSION_KEY = "authos_qr_tokens"


def utc_now():
    return datetime.now(timezone.utc)


def normalize_cpf(value):
    digits = CPF_DIGITS.sub("", value or "")
    if not _is_valid_cpf(digits):
        raise ValueError("CPF invalido.")
    return digits


def format_cpf(value):
    digits = CPF_DIGITS.sub("", value or "")
    if len(digits) != 11:
        return value or ""
    return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _is_valid_cpf(cpf):
    if len(cpf) != 11:
        return False
    if cpf == cpf[0] * 11:
        return False

    first_digit = _cpf_check_digit(cpf[:9], weight_start=10)
    second_digit = _cpf_check_digit(cpf[:9] + str(first_digit), weight_start=11)
    return cpf[-2:] == f"{first_digit}{second_digit}"


def _cpf_check_digit(partial, weight_start):
    total = sum(int(number) * weight for number, weight in zip(partial, range(weight_start, 1, -1)))
    remainder = (total * 10) % 11
    return 0 if remainder == 10 else remainder


class AdminUser(UserMixin, db.Model):
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class QrRecord(db.Model):
    __tablename__ = "qr_records"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(180), nullable=False)
    cpf = db.Column(db.String(11), nullable=False, index=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    qr_png = db.Column(db.LargeBinary, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    @property
    def formatted_cpf(self):
        return format_cpf(self.cpf)

    @property
    def status_label(self):
        return "Ativo" if self.is_active else "Revogado"


class LoginForm(FlaskForm):
    username = StringField("Usuario", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Senha", validators=[DataRequired(), Length(max=256)])
    submit = SubmitField("Entrar")


class QrRecordForm(FlaskForm):
    full_name = StringField("Nome completo", validators=[DataRequired(), Length(max=180)])
    cpf = StringField("CPF", validators=[DataRequired(), Length(min=11, max=14)])
    submit = SubmitField("Gerar QR Code")

    def validate_cpf(self, field):
        try:
            self.normalized_cpf = normalize_cpf(field.data)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc


class LogoutForm(FlaskForm):
    submit = SubmitField("Sair")


class DeleteRecordForm(FlaskForm):
    submit = SubmitField("Apagar definitivamente")


class TokenGenerationError(RuntimeError):
    pass


def build_public_url(token):
    base_url = current_app_config("BASE_URL").rstrip("/")
    return f"{base_url}{url_for('public.validate_qr', token=token)}"


def current_app_config(key):
    from flask import current_app

    return current_app.config[key]


def create_qr_record(full_name, cpf, token_factory=None, max_attempts=10):
    token_factory = token_factory or secrets.token_urlsafe
    normalized_cpf = normalize_cpf(cpf)
    clean_name = " ".join((full_name or "").split())

    if not clean_name:
        raise ValueError("Nome completo e obrigatorio.")

    for _ in range(max_attempts):
        token = token_factory(32)
        token_digest = hash_token(token)

        if QrRecord.query.filter_by(token_hash=token_digest).first():
            continue

        record = QrRecord(full_name=clean_name, cpf=normalized_cpf, token_hash=token_digest)
        db.session.add(record)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            continue

        return record, token

    raise TokenGenerationError("Nao foi possivel gerar um QR Code unico.")


def revoke_qr_record(record):
    if not record.is_active:
        return record

    record.is_active = False
    record.revoked_at = utc_now()
    db.session.commit()
    return record


def qr_png_for_url(url):
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    image = qr.make_image(fill_color="black", back_color="white")
    output = BytesIO()
    image.save(output, format="PNG")
    output.seek(0)
    return output


def qr_png_bytes_for_url(url):
    return qr_png_for_url(url).getvalue()


@admin_bp.app_context_processor
def inject_forms():
    return {"logout_form": LogoutForm(), "delete_record_form": DeleteRecordForm()}


@admin_bp.get("/")
def admin_index():
    if current_user.is_authenticated:
        return redirect(url_for("admin.qrcodes"))
    return redirect(url_for("admin.login"))


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin.qrcodes"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        user = AdminUser.query.filter_by(username=username).first()

        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Login realizado com sucesso.", "success")
            return redirect(_safe_next_url() or url_for("admin.qrcodes"))

        flash("Usuario ou senha invalidos.", "error")

    return render_template("admin/login.html", form=form)


@admin_bp.post("/logout")
@login_required
def logout():
    form = LogoutForm()
    if form.validate_on_submit():
        logout_user()
        flash("Sessao encerrada.", "success")
        return redirect(url_for("admin.login"))
    abort(400)


@admin_bp.get("/qrcodes")
@login_required
def qrcodes():
    records = QrRecord.query.order_by(QrRecord.created_at.desc()).all()
    return render_template("admin/qrcodes.html", records=records)


@admin_bp.route("/qrcodes/new", methods=["GET", "POST"])
@login_required
def new_qrcode():
    form = QrRecordForm()
    if form.validate_on_submit():
        try:
            record, token = create_qr_record(form.full_name.data, form.normalized_cpf)
        except (TokenGenerationError, ValueError) as exc:
            flash(str(exc), "error")
        else:
            record.qr_png = qr_png_bytes_for_url(build_public_url(token))
            db.session.commit()
            _remember_token(record.id, token)
            flash("QR Code criado com sucesso.", "success")
            return redirect(url_for("admin.qrcode_detail", record_id=record.id))

    return render_template("admin/new_qrcode.html", form=form)


@admin_bp.get("/qrcodes/<int:record_id>")
@login_required
def qrcode_detail(record_id):
    record = db.get_or_404(QrRecord, record_id)
    token = _remembered_token_for(record)
    public_url = build_public_url(token) if token else None
    return render_template("admin/qrcode_detail.html", record=record, public_url=public_url)


@admin_bp.get("/qrcodes/<int:record_id>/png")
@login_required
def qrcode_png(record_id):
    record = db.get_or_404(QrRecord, record_id)

    if not record.is_active:
        abort(404)

    if record.qr_png:
        image = BytesIO(record.qr_png)
    else:
        token = _remembered_token_for(record)
        if not token:
            abort(404)
        image = qr_png_for_url(build_public_url(token))
        record.qr_png = image.getvalue()
        image.seek(0)
        db.session.commit()

    return send_file(
        image,
        mimetype="image/png",
        as_attachment=request.args.get("download") == "1",
        download_name=f"authos-qr-{record.id}.png",
    )


@admin_bp.post("/qrcodes/<int:record_id>/revoke")
@login_required
def revoke_qrcode(record_id):
    record = db.get_or_404(QrRecord, record_id)
    revoke_qr_record(record)
    _forget_token(record.id)
    flash("QR Code revogado.", "success")
    return redirect(url_for("admin.qrcode_detail", record_id=record.id))


@admin_bp.get("/qrcodes/<int:record_id>/delete")
@login_required
def delete_qrcode_confirm(record_id):
    record = db.get_or_404(QrRecord, record_id)
    return render_template("admin/delete_qrcode.html", record=record, form=DeleteRecordForm())


@admin_bp.post("/qrcodes/<int:record_id>/delete")
@login_required
def delete_qrcode(record_id):
    form = DeleteRecordForm()
    if not form.validate_on_submit():
        abort(400)

    record = db.get_or_404(QrRecord, record_id)
    _forget_token(record.id)
    db.session.delete(record)
    db.session.commit()
    flash("Registro apagado.", "success")
    return redirect(url_for("admin.qrcodes"))


@public_bp.get("/v/<token>")
def validate_qr(token):
    token_digest = hash_token(token)
    record = QrRecord.query.filter_by(token_hash=token_digest, is_active=True).first()
    if not record:
        return render_template("public/invalid.html"), 404

    return render_template("public/valid.html", record=record)


def _safe_next_url():
    target = request.args.get("next")
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


def _remember_token(record_id, token):
    tokens = session.get(TOKEN_SESSION_KEY, {})
    tokens[str(record_id)] = token
    session[TOKEN_SESSION_KEY] = dict(list(tokens.items())[-20:])
    session.modified = True


def _remembered_token_for(record):
    token = session.get(TOKEN_SESSION_KEY, {}).get(str(record.id))
    if token and hash_token(token) == record.token_hash:
        return token
    return None


def _forget_token(record_id):
    tokens = session.get(TOKEN_SESSION_KEY, {})
    tokens.pop(str(record_id), None)
    session[TOKEN_SESSION_KEY] = tokens
    session.modified = True


def create_app(test_config=None):
    load_dotenv()

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///authos.sqlite3"),
        BASE_URL=os.environ.get("BASE_URL", "validadoreducabrasil.com.br"),
        SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", True),
        WTF_CSRF_ENABLED=_env_bool("WTF_CSRF_ENABLED", True),
    )

    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.jinja_loader = DictLoader(TEMPLATES)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    _ensure_schema(app)

    login_manager.login_view = "admin.login"
    login_manager.login_message = "Entre como administrador para continuar."
    login_manager.login_message_category = "warning"

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(AdminUser, int(user_id))
        except (TypeError, ValueError):
            return None

    app.register_blueprint(admin_bp)
    app.register_blueprint(public_bp)

    @app.get("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("admin.qrcodes"))
        return redirect(url_for("admin.login"))

    @app.get("/styles.css")
    def styles_css():
        return Response(STYLES, mimetype="text/css")

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self'; style-src 'self'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        flash("Sessao expirada ou formulario invalido. Tente novamente.", "error")
        return redirect(url_for("admin.login"))

    _register_cli(app)
    return app


def _register_cli(app):
    @app.cli.command("init-db")
    def init_db_command():
        _ensure_schema(app)
        click.echo("Banco de dados inicializado.")

    @app.cli.command("create-admin")
    @click.argument("username")
    @click.option(
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Senha do administrador.",
    )
    def create_admin_command(username, password):
        username = username.strip()
        if not username:
            raise click.ClickException("Informe um nome de usuario valido.")

        existing = AdminUser.query.filter_by(username=username).first()
        if existing:
            raise click.ClickException("Este usuario admin ja existe.")

        user = AdminUser(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Admin criado: {username}")


def _ensure_schema(app):
    with app.app_context():
        db.create_all()
        if db.engine.dialect.name != "sqlite":
            return

        columns = {
            row[1]
            for row in db.session.execute(text("PRAGMA table_info(qr_records)")).fetchall()
        }
        if "qr_png" not in columns:
            db.session.execute(text("ALTER TABLE qr_records ADD COLUMN qr_png BLOB"))
            db.session.commit()

TEMPLATES = {
    "base.html": """
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Authos{% endblock %}</title>
  <link rel="stylesheet" href="{{ url_for('styles_css') }}">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="{{ url_for('admin.qrcodes') if current_user.is_authenticated else url_for('admin.login') }}">Authos</a>
    {% if current_user.is_authenticated and logout_form is defined %}
      <nav class="nav">
        <a href="{{ url_for('admin.qrcodes') }}">Registros</a>
        <a href="{{ url_for('admin.new_qrcode') }}">Novo QR</a>
        <form method="post" action="{{ url_for('admin.logout') }}">
          {{ logout_form.csrf_token }}
          <button class="link-button" type="submit">Sair</button>
        </form>
      </nav>
    {% endif %}
  </header>

  <main class="shell">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="flash-stack" role="status" aria-live="polite">
          {% for category, message in messages %}
            <p class="flash flash-{{ category }}">{{ message }}</p>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </main>

  <footer class="site-footer">
    <span>validadoreducabrasil.com.br</span>
    <a href="mailto:validadoreducabrasil@yahoo.com">validadoreducabrasil@yahoo.com</a>
  </footer>
</body>
</html>
""",
    "admin/login.html": """
{% extends "base.html" %}
{% block title %}Login admin - Authos{% endblock %}
{% block content %}
<section class="auth-panel">
  <h1>Login admin</h1>
  <form class="form" method="post" novalidate>
    {{ form.hidden_tag() }}

    <label for="{{ form.username.id }}">{{ form.username.label.text }}</label>
    {{ form.username(autocomplete="username") }}
    {% for error in form.username.errors %}
      <span class="field-error">{{ error }}</span>
    {% endfor %}

    <label for="{{ form.password.id }}">{{ form.password.label.text }}</label>
    {{ form.password(autocomplete="current-password") }}
    {% for error in form.password.errors %}
      <span class="field-error">{{ error }}</span>
    {% endfor %}

    {{ form.submit(class="button button-primary") }}
  </form>
</section>
{% endblock %}
""",
    "admin/qrcodes.html": """
{% extends "base.html" %}
{% block title %}Registros - Authos{% endblock %}
{% block content %}
<section class="page-heading">
  <div>
    <p class="eyebrow">Admin</p>
    <h1>QR Codes</h1>
  </div>
  <a class="button button-primary" href="{{ url_for('admin.new_qrcode') }}">Criar QR Code</a>
</section>

{% if records %}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Nome</th>
          <th>CPF</th>
          <th>Status</th>
          <th>Criado em</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {% for record in records %}
          <tr>
            <td>{{ record.full_name }}</td>
            <td>{{ record.formatted_cpf }}</td>
            <td><span class="status {{ 'status-active' if record.is_active else 'status-revoked' }}">{{ record.status_label }}</span></td>
            <td>{{ record.created_at.strftime("%d/%m/%Y %H:%M") }}</td>
            <td class="align-right">
              <span class="row-actions">
                <a href="{{ url_for('admin.qrcode_detail', record_id=record.id) }}">Abrir</a>
                <a class="danger-text" href="{{ url_for('admin.delete_qrcode_confirm', record_id=record.id) }}">Apagar</a>
              </span>
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
{% else %}
  <section class="empty-state">
    <h2>Nenhum QR Code criado</h2>
    <a class="button button-primary" href="{{ url_for('admin.new_qrcode') }}">Criar primeiro QR</a>
  </section>
{% endif %}
{% endblock %}
""",
    "admin/new_qrcode.html": """
{% extends "base.html" %}
{% block title %}Novo QR Code - Authos{% endblock %}
{% block content %}
<section class="page-heading">
  <div>
    <p class="eyebrow">Novo registro</p>
    <h1>Criar QR Code</h1>
  </div>
</section>

<section class="form-panel">
  <form class="form" method="post" novalidate>
    {{ form.hidden_tag() }}

    <label for="{{ form.full_name.id }}">{{ form.full_name.label.text }}</label>
    {{ form.full_name(autocomplete="name", placeholder="Nome da pessoa") }}
    {% for error in form.full_name.errors %}
      <span class="field-error">{{ error }}</span>
    {% endfor %}

    <label for="{{ form.cpf.id }}">{{ form.cpf.label.text }}</label>
    {{ form.cpf(inputmode="numeric", autocomplete="off", placeholder="000.000.000-00") }}
    {% for error in form.cpf.errors %}
      <span class="field-error">{{ error }}</span>
    {% endfor %}

    <div class="actions">
      {{ form.submit(class="button button-primary") }}
      <a class="button button-secondary" href="{{ url_for('admin.qrcodes') }}">Cancelar</a>
    </div>
  </form>
</section>
{% endblock %}
""",
    "admin/qrcode_detail.html": """
{% extends "base.html" %}
{% block title %}QR Code - Authos{% endblock %}
{% block content %}
<section class="page-heading">
  <div>
    <p class="eyebrow">Registro</p>
    <h1>{{ record.full_name }}</h1>
  </div>
  <span class="status {{ 'status-active' if record.is_active else 'status-revoked' }}">{{ record.status_label }}</span>
</section>

<section class="detail-grid">
  <div class="detail-panel">
    <dl class="facts">
      <div>
        <dt>CPF</dt>
        <dd>{{ record.formatted_cpf }}</dd>
      </div>
      <div>
        <dt>Criado em</dt>
        <dd>{{ record.created_at.strftime("%d/%m/%Y %H:%M") }}</dd>
      </div>
      {% if record.revoked_at %}
        <div>
          <dt>Revogado em</dt>
          <dd>{{ record.revoked_at.strftime("%d/%m/%Y %H:%M") }}</dd>
        </div>
      {% endif %}
    </dl>

    <div class="actions">
      {% if record.is_active %}
        <form method="post" action="{{ url_for('admin.revoke_qrcode', record_id=record.id) }}">
          {{ logout_form.csrf_token }}
          <button class="button button-danger" type="submit">Revogar QR Code</button>
        </form>
      {% endif %}
      <a class="button button-outline-danger" href="{{ url_for('admin.delete_qrcode_confirm', record_id=record.id) }}">Apagar registro</a>
    </div>
  </div>

  <div class="qr-panel">
    {% if record.is_active and (public_url or record.qr_png) %}
      <img class="qr-image" src="{{ url_for('admin.qrcode_png', record_id=record.id) }}" alt="QR Code Authos">
      {% if public_url %}
        <label for="public-url">URL publica</label>
        <input id="public-url" value="{{ public_url }}" readonly>
      {% else %}
        <p class="muted-note">URL indisponivel nesta sessao, mas o PNG salvo pode ser baixado.</p>
      {% endif %}
      <a class="button button-primary" href="{{ url_for('admin.qrcode_png', record_id=record.id, download=1) }}">Baixar PNG</a>
    {% else %}
      <div class="empty-state compact">
        <h2>Imagem indisponivel</h2>
        <p>Crie outro QR Code para gerar uma nova imagem.</p>
      </div>
    {% endif %}
  </div>
</section>
{% endblock %}
""",
    "admin/delete_qrcode.html": """
{% extends "base.html" %}
{% block title %}Apagar registro - Authos{% endblock %}
{% block content %}
<section class="page-heading">
  <div>
    <p class="eyebrow">Confirmacao</p>
    <h1>Apagar registro</h1>
  </div>
</section>

<section class="form-panel danger-panel">
  <p>Esta acao remove o registro, o status, a imagem PNG salva e torna a URL publica invalida.</p>
  <dl class="facts">
    <div>
      <dt>Nome</dt>
      <dd>{{ record.full_name }}</dd>
    </div>
    <div>
      <dt>CPF</dt>
      <dd>{{ record.formatted_cpf }}</dd>
    </div>
    <div>
      <dt>Status</dt>
      <dd>{{ record.status_label }}</dd>
    </div>
  </dl>

  <form method="post" action="{{ url_for('admin.delete_qrcode', record_id=record.id) }}">
    {{ form.hidden_tag() }}
    <div class="actions">
      {{ form.submit(class="button button-danger") }}
      <a class="button button-secondary" href="{{ url_for('admin.qrcode_detail', record_id=record.id) }}">Cancelar</a>
    </div>
  </form>
</section>
{% endblock %}
""",
    "public/valid.html": """
{% extends "base.html" %}
{% block title %}QR valido - Authos{% endblock %}
{% block content %}
<section class="verification">
  <p class="eyebrow">QR valido</p>
  <h1>Documento confirmado</h1>
  <dl class="facts public-facts">
    <div>
      <dt>Nome</dt>
      <dd>{{ record.full_name }}</dd>
    </div>
    <div>
      <dt>CPF</dt>
      <dd>{{ record.formatted_cpf }}</dd>
    </div>
  </dl>
</section>
{% endblock %}
""",
    "public/invalid.html": """
{% extends "base.html" %}
{% block title %}QR invalido - Authos{% endblock %}
{% block content %}
<section class="verification invalid">
  <p class="eyebrow">QR invalido</p>
  <h1>Codigo nao encontrado</h1>
  <p>Este QR Code nao esta ativo no Authos.</p>
</section>
{% endblock %}
""",
}


STYLES = """
:root {
  --bg: #f6f7f9;
  --surface: #ffffff;
  --ink: #17202a;
  --muted: #667085;
  --line: #d8dee8;
  --primary: #0f766e;
  --primary-dark: #115e59;
  --danger: #b42318;
  --danger-soft: #fff1f0;
  --success-soft: #ecfdf3;
  --warning-soft: #fffaeb;
  --shadow: 0 18px 38px rgba(23, 32, 42, 0.08);
}

* {
  box-sizing: border-box;
}

body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: Arial, Helvetica, sans-serif;
  font-size: 16px;
  line-height: 1.5;
}

a {
  color: var(--primary-dark);
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 64px;
  padding: 0 32px;
  border-bottom: 1px solid var(--line);
  background: var(--surface);
}

.brand {
  color: var(--ink);
  font-size: 1.25rem;
  font-weight: 700;
  letter-spacing: 0;
}

.nav {
  display: flex;
  align-items: center;
  gap: 18px;
}

.shell {
  flex: 1;
  width: min(1120px, calc(100% - 32px));
  margin: 32px auto;
}

.site-footer {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-wrap: wrap;
  gap: 8px 18px;
  width: min(1120px, calc(100% - 32px));
  margin: 0 auto 24px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
  color: var(--muted);
  font-size: 0.92rem;
  text-align: center;
}

.page-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 24px;
}

h1,
h2,
p {
  margin-top: 0;
}

h1 {
  margin-bottom: 0;
  font-size: 2rem;
  line-height: 1.2;
  letter-spacing: 0;
}

h2 {
  font-size: 1.25rem;
  letter-spacing: 0;
}

.eyebrow {
  margin-bottom: 6px;
  color: var(--muted);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.auth-panel,
.form-panel,
.detail-panel,
.qr-panel,
.verification,
.empty-state,
.table-wrap {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
  box-shadow: var(--shadow);
}

.auth-panel {
  width: min(420px, 100%);
  margin: 72px auto;
  padding: 28px;
}

.form-panel {
  max-width: 640px;
  padding: 28px;
}

.danger-panel {
  border-color: #fecdca;
}

.form {
  display: grid;
  gap: 10px;
}

label {
  color: var(--ink);
  font-size: 0.92rem;
  font-weight: 700;
}

input {
  width: 100%;
  min-height: 44px;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 10px 12px;
  color: var(--ink);
  font: inherit;
  background: #ffffff;
}

input:focus {
  outline: 3px solid rgba(15, 118, 110, 0.18);
  border-color: var(--primary);
}

.field-error {
  color: var(--danger);
  font-size: 0.88rem;
}

.muted-note {
  margin: 0;
  color: var(--muted);
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 12px;
}

.button,
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 42px;
  border: 1px solid transparent;
  border-radius: 6px;
  padding: 9px 14px;
  font: inherit;
  font-weight: 700;
  cursor: pointer;
  text-decoration: none;
  white-space: nowrap;
}

.button:hover {
  text-decoration: none;
}

.button-primary {
  background: var(--primary);
  color: #ffffff;
}

.button-primary:hover {
  background: var(--primary-dark);
}

.button-secondary {
  border-color: var(--line);
  background: var(--surface);
  color: var(--ink);
}

.button-danger {
  background: var(--danger);
  color: #ffffff;
}

.button-outline-danger {
  border-color: #fecdca;
  background: var(--danger-soft);
  color: var(--danger);
}

.button-outline-danger:hover {
  border-color: var(--danger);
}

.link-button {
  min-height: auto;
  border: 0;
  padding: 0;
  background: transparent;
  color: var(--primary-dark);
}

.flash-stack {
  display: grid;
  gap: 10px;
  margin-bottom: 18px;
}

.flash {
  margin: 0;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px 14px;
  background: var(--surface);
}

.flash-success {
  border-color: #abefc6;
  background: var(--success-soft);
}

.flash-error,
.flash-warning {
  border-color: #fedf89;
  background: var(--warning-soft);
}

.table-wrap {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th,
td {
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: middle;
}

th {
  color: var(--muted);
  font-size: 0.82rem;
  text-transform: uppercase;
}

tr:last-child td {
  border-bottom: 0;
}

.align-right {
  text-align: right;
}

.row-actions {
  display: inline-flex;
  gap: 12px;
  white-space: nowrap;
}

.danger-text {
  color: var(--danger);
  font-weight: 700;
}

.status {
  display: inline-flex;
  align-items: center;
  min-height: 28px;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 0.85rem;
  font-weight: 700;
}

.status-active {
  background: var(--success-soft);
  color: #067647;
}

.status-revoked {
  background: var(--danger-soft);
  color: var(--danger);
}

.detail-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(280px, 360px);
  gap: 18px;
}

.detail-panel,
.qr-panel,
.empty-state,
.verification {
  padding: 24px;
}

.facts {
  display: grid;
  gap: 16px;
  margin: 0 0 24px;
}

.facts div {
  display: grid;
  gap: 4px;
}

.facts dt {
  color: var(--muted);
  font-size: 0.82rem;
  font-weight: 700;
  text-transform: uppercase;
}

.facts dd {
  margin: 0;
  font-size: 1.06rem;
  font-weight: 700;
}

.qr-panel {
  display: grid;
  gap: 14px;
  align-content: start;
}

.qr-image {
  width: 100%;
  max-width: 312px;
  aspect-ratio: 1 / 1;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 10px;
  background: #ffffff;
}

.empty-state {
  display: grid;
  gap: 12px;
  justify-items: start;
}

.empty-state.compact {
  box-shadow: none;
}

.verification {
  max-width: 680px;
  margin: 56px auto;
}

.public-facts {
  margin-bottom: 0;
}

.invalid {
  border-color: #fecdca;
  background: #fffafa;
}

@media (max-width: 760px) {
  .topbar,
  .page-heading,
  .nav {
    align-items: flex-start;
    flex-direction: column;
  }

  .topbar {
    gap: 12px;
    padding: 16px;
  }

  .shell {
    margin: 20px auto;
  }

  .detail-grid {
    grid-template-columns: 1fr;
  }

  h1 {
    font-size: 1.55rem;
  }
}
"""


app = create_app()


if __name__ == "__main__":
    app.run()
