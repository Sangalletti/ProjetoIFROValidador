import hashlib
import logging
import os
import re
import secrets
from collections import defaultdict, deque
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from time import monotonic

import click
import qrcode
from dotenv import load_dotenv
from flask import (
    Blueprint,
    Flask,
    abort,
    current_app,
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
from jinja2 import FileSystemLoader
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


CERTIFICATE_PDF_MAX_BYTES = 10 * 1024 * 1024
PDF_SIGNATURE = b"%PDF-"
LOGIN_IP_RATE_LIMITS = ((60, 10), (3600, 50))
LOGIN_USER_RATE_LIMITS = ((60, 5), (3600, 20))
_rate_limit_events = defaultdict(deque)


class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    PREFERRED_URL_SCHEME = "https"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = 3600
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = CERTIFICATE_PDF_MAX_BYTES
    TRUST_PROXY = False
    PROXY_FIX_X_FOR = 1
    PROXY_FIX_X_PROTO = 1
    PROXY_FIX_X_HOST = 1
    DEBUG = False
    TESTING = False


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
public_bp = Blueprint("public", __name__)
CPF_DIGITS = re.compile(r"\D+")
TOKEN_SESSION_KEY = "validador_educa_brasil_qr_tokens"


def utc_now():
    return datetime.now(timezone.utc)


def normalize_cpf(value):
    digits = CPF_DIGITS.sub("", value or "")
    if not _is_valid_cpf(digits):
        raise ValueError("CPF inválido.")
    return digits


def format_cpf(value):
    digits = CPF_DIGITS.sub("", value or "")
    if len(digits) != 11:
        return value or ""
    return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"


def mask_cpf(value):
    digits = CPF_DIGITS.sub("", value or "")
    if len(digits) != 11:
        return ""
    return f"***.***.***-{digits[-2:]}"


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

    certificate = db.relationship(
        "Certificate",
        back_populates="qr_record",
        uselist=False,
        cascade="all, delete-orphan",
    )

    @property
    def formatted_cpf(self):
        return format_cpf(self.cpf)

    @property
    def masked_cpf(self):
        return mask_cpf(self.cpf)

    @property
    def status_label(self):
        return "Ativo" if self.is_active else "Revogado"


class Certificate(db.Model):
    __tablename__ = "certificates"

    id = db.Column(db.Integer, primary_key=True)

    qr_record_id = db.Column(
        db.Integer,
        db.ForeignKey("qr_records.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    titular = db.Column(db.String(200), nullable=False)
    tipo = db.Column(db.String(200), nullable=False)
    data_emissao = db.Column(db.DateTime, nullable=False)
    curso = db.Column(db.String(200), nullable=False)
    instituicao = db.Column(db.String(200), nullable=False)

    pdf_filename = db.Column(db.String(255))
    pdf_data = db.Column(db.LargeBinary)

    qr_record = db.relationship("QrRecord", back_populates="certificate")


class LoginForm(FlaskForm):
    username = StringField("Usuário", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Senha", validators=[DataRequired(), Length(min=8, max=256)])
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


def normalize_base_url(base_url):
    base_url = (base_url or "").strip().rstrip("/")
    if not base_url:
        return "https://www.validadoreducabrasil.com.br"
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    for scheme in ("https://", "http://"):
        without_www = f"{scheme}validadoreducabrasil.com.br"
        with_www = f"{scheme}www.validadoreducabrasil.com.br"
        if base_url == without_www or base_url.startswith(f"{without_www}/"):
            return base_url.replace(without_www, with_www, 1).rstrip("/")

    return base_url


def build_public_url(token):
    base_url = normalize_base_url(current_app_config("BASE_URL"))
    return f"{base_url}{url_for('public.validate_qr', token=token)}"


def current_app_config(key):
    return current_app.config[key]


def create_qr_record(full_name, cpf, token_factory=None, max_attempts=10):
    token_factory = token_factory or secrets.token_urlsafe
    normalized_cpf = normalize_cpf(cpf)
    clean_name = " ".join((full_name or "").split())

    if not clean_name:
        raise ValueError("Nome completo é obrigatório.")

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

    raise TokenGenerationError("Não foi possível gerar um QR Code único.")


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


def _safe_pdf_filename(filename):
    sanitized = secure_filename(filename or "")
    if not sanitized:
        return ""
    return sanitized


def _read_certificate_pdf(upload):
    pdf_bytes = upload.read(CERTIFICATE_PDF_MAX_BYTES + 1)
    if len(pdf_bytes) > CERTIFICATE_PDF_MAX_BYTES:
        raise ValueError("O arquivo PDF deve ter no máximo 10 MB.")
    if not pdf_bytes:
        raise ValueError("O arquivo PDF está vazio.")
    if not pdf_bytes.startswith(PDF_SIGNATURE):
        raise ValueError("Arquivo PDF inválido.")
    return pdf_bytes


def _send_certificate_pdf(certificate):
    filename = _safe_pdf_filename(certificate.pdf_filename) or "certificado.pdf"
    if not filename.lower().endswith(".pdf"):
        filename = f"{filename}.pdf"

    return send_file(
        BytesIO(certificate.pdf_data),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


def _find_active_record_by_token(token):
    token = (token or "").strip()
    if not token:
        return None

    token_digest = hash_token(token)
    return QrRecord.query.filter_by(
        token_hash=token_digest,
        is_active=True,
    ).first()


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
        if _login_rate_limited(username):
            current_app.logger.warning(f"Login bloqueado por limite de tentativas: {username}")
            flash("Muitas tentativas de login. Aguarde alguns minutos e tente novamente.", "error")
            return render_template("admin/login.html", form=form), 429

        user = AdminUser.query.filter_by(username=username).first()

        if user and user.check_password(form.password.data):
            _clear_login_rate_limit(username)
            session.permanent = True
            login_user(user)
            current_app.logger.info(f"Login bem-sucedido: {username}")
            flash("Login realizado com sucesso.", "success")
            return redirect(_safe_next_url() or url_for("admin.qrcodes"))

        current_app.logger.warning(f"Tentativa de login falhou: {username}")
        flash("Usuário ou senha inválidos.", "error")

    return render_template("admin/login.html", form=form)


@admin_bp.post("/logout")
@login_required
def logout():
    form = LogoutForm()
    if form.validate_on_submit():
        username = current_user.username
        logout_user()
        current_app.logger.info(f"Logout: {username}")
        flash("Sessão encerrada.", "success")
        return redirect(url_for("admin.login"))
    abort(400)


@admin_bp.get("/qrcodes")
@login_required
def qrcodes():
    records = QrRecord.query.order_by(QrRecord.created_at.desc()).all()
    return render_template("admin/qrcodes.html", records=records)

def _parse_emission_datetime(value):
    if not value:
        raise ValueError("Informe a data de emissão.")
    return datetime.fromisoformat(value)


def _available_qr_records_for_certificate():
    return (
        QrRecord.query.filter_by(is_active=True)
        .outerjoin(Certificate)
        .filter(Certificate.id.is_(None))
        .order_by(QrRecord.full_name)
        .all()
    )


@admin_bp.route("/certificados/cadastrar", methods=["GET", "POST"])
@login_required
def cadastrar_certificado():
    records = _available_qr_records_for_certificate()

    if request.method == "POST":
        qr_record_id = request.form.get("qr_record_id", "").strip()
        titular = request.form.get("titular", "").strip()
        tipo = request.form.get("tipo", "").strip()
        curso = request.form.get("curso", "").strip()
        instituicao = request.form.get("instituicao", "").strip()
        pdf = request.files.get("pdf_certificado")

        if not qr_record_id:
            flash("Selecione um QR Code.", "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        record = QrRecord.query.filter_by(id=qr_record_id, is_active=True).first()
        if not record:
            flash("QR Code inválido ou inativo.", "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        if Certificate.query.filter_by(qr_record_id=record.id).first():
            flash("Este QR Code já possui um certificado vinculado.", "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        if not pdf or not pdf.filename:
            flash("Envie o arquivo PDF do certificado.", "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        pdf_filename = _safe_pdf_filename(pdf.filename)
        if not pdf_filename or not pdf_filename.lower().endswith(".pdf"):
            flash("O arquivo deve estar no formato PDF.", "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        try:
            pdf_bytes = _read_certificate_pdf(pdf)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        try:
            data_emissao = _parse_emission_datetime(request.form.get("data_emissao"))
        except ValueError:
            flash("Data de emissão inválida.", "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        if not all([titular, tipo, curso, instituicao]):
            flash("Preencha todos os campos obrigatórios.", "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        certificate = Certificate(
            qr_record_id=record.id,
            titular=titular,
            tipo=tipo,
            data_emissao=data_emissao,
            curso=curso,
            instituicao=instituicao,
            pdf_filename=pdf_filename,
            pdf_data=pdf_bytes,
        )

        db.session.add(certificate)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Este QR Code já possui um certificado vinculado.", "error")
            return redirect(url_for("admin.cadastrar_certificado"))

        flash("Certificado cadastrado com sucesso.", "success")
        return redirect(url_for("admin.certificado_detail", certificate_id=certificate.id))

    return render_template("admin/cadastrar_certificado.html", records=records)

@public_bp.get("/certificados/<int:certificate_id>")
def download_public_certificate(certificate_id):
    record = _find_active_record_by_token(request.args.get("token"))
    if not record:
        abort(404)

    certificate = Certificate.query.filter_by(
        id=certificate_id,
        qr_record_id=record.id,
    ).first()
    if not certificate or not certificate.pdf_data:
        abort(404)

    return _send_certificate_pdf(certificate)


@public_bp.get("/v/<token>/certificado")
def download_public_certificate_for_token(token):
    record = _find_active_record_by_token(token)
    if not record:
        abort(404)

    certificate = Certificate.query.filter_by(qr_record_id=record.id).first()
    if not certificate or not certificate.pdf_data:
        abort(404)

    return _send_certificate_pdf(certificate)

@public_bp.get("/v/<token>")
def validate_qr(token):

    record = _find_active_record_by_token(token)
    if not record:
        return render_template("public/invalid.html"), 404

    certificate = Certificate.query.filter_by(
        qr_record_id=record.id
    ).first()

    return render_template(
        "public/valid.html",
        record=record,
        certificate=certificate,
        token=token,
    )

@admin_bp.route("/qrcodes/new", methods=["GET", "POST"])
@login_required
def new_qrcode():
    form = QrRecordForm()
    if form.validate_on_submit():
        try:
            record, token = create_qr_record(form.full_name.data, form.normalized_cpf)
        except (TokenGenerationError, ValueError) as exc:
            current_app.logger.error(f"Erro ao criar QR: {str(exc)}")
            flash(str(exc), "error")
        else:
            record.qr_png = qr_png_bytes_for_url(build_public_url(token))
            db.session.commit()
            _remember_token(record.id, token)
            current_app.logger.info(f"QR Code criado: ID={record.id}, CPF={record.formatted_cpf}")
            flash("QR Code criado com sucesso.", "success")
            return redirect(url_for("admin.qrcode_detail", record_id=record.id))

    return render_template("admin/new_qrcode.html", form=form)

@admin_bp.get("/certificados/<int:certificate_id>")
@login_required
def certificado_detail(certificate_id):
    certificate = db.get_or_404(Certificate, certificate_id)
    return render_template("admin/certificado_detail.html", certificate=certificate)


@admin_bp.get("/certificados/<int:certificate_id>/pdf")
@login_required
def download_certificado(certificate_id):
    certificate = db.get_or_404(Certificate, certificate_id)
    if not certificate.pdf_data:
        abort(404)
    return _send_certificate_pdf(certificate)


@admin_bp.get("/certificados/<int:certificate_id>/delete")
@login_required
def delete_certificado_confirm(certificate_id):
    certificate = db.get_or_404(Certificate, certificate_id)
    return render_template(
        "admin/delete_certificado.html",
        certificate=certificate,
        form=DeleteRecordForm(),
    )


@admin_bp.post("/certificados/<int:certificate_id>/delete")
@login_required
def delete_certificado(certificate_id):
    form = DeleteRecordForm()
    if not form.validate_on_submit():
        abort(400)

    certificate = db.get_or_404(Certificate, certificate_id)
    titular = certificate.titular
    db.session.delete(certificate)
    db.session.commit()
    current_app.logger.info(f"Certificado deletado: ID={certificate_id}, titular={titular}")
    flash("Certificado removido.", "success")
    return redirect(url_for("admin.qrcodes"))


@admin_bp.get("/qrcodes/<int:record_id>")
@login_required
def qrcode_detail(record_id):
    record = db.get_or_404(QrRecord, record_id)
    token = _remembered_token_for(record)
    public_url = build_public_url(token) if token else None
    certificate = Certificate.query.filter_by(qr_record_id=record.id).first()
    return render_template(
        "admin/qrcode_detail.html",
        record=record,
        public_url=public_url,
        certificate=certificate,
    )


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
        download_name=f"validador-educa-brasil-qr-{record.id}.png",
    )


@admin_bp.post("/qrcodes/<int:record_id>/revoke")
@login_required
def revoke_qrcode(record_id):
    record = db.get_or_404(QrRecord, record_id)
    revoke_qr_record(record)
    _forget_token(record.id)
    current_app.logger.info(f"QR Code revogado: ID={record_id}, CPF={record.formatted_cpf}")
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
    cpf_formatted = record.formatted_cpf
    _forget_token(record.id)
    db.session.delete(record)
    db.session.commit()
    current_app.logger.info(f"QR Code deletado: ID={record_id}, CPF={cpf_formatted}")
    flash("Registro apagado.", "success")
    return redirect(url_for("admin.qrcodes"))


def _client_rate_limit_key():
    return request.remote_addr or "unknown"


def _record_rate_limit_event(scope, key, limits):
    now = monotonic()
    bucket = _rate_limit_events[(scope, key)]
    max_window = max(window for window, _ in limits)

    while bucket and now - bucket[0] > max_window:
        bucket.popleft()

    is_limited = any(
        sum(1 for event_time in bucket if now - event_time <= window) >= max_events
        for window, max_events in limits
    )
    bucket.append(now)
    return is_limited


def _clear_rate_limit(scope, key):
    _rate_limit_events.pop((scope, key), None)


def _login_rate_limited(username):
    normalized_username = (username or "").strip().lower()
    ip_limited = _record_rate_limit_event(
        "login-ip",
        _client_rate_limit_key(),
        LOGIN_IP_RATE_LIMITS,
    )
    user_limited = _record_rate_limit_event(
        "login-user",
        normalized_username,
        LOGIN_USER_RATE_LIMITS,
    )
    return ip_limited or user_limited


def _clear_login_rate_limit(username):
    normalized_username = (username or "").strip().lower()
    _clear_rate_limit("login-ip", _client_rate_limit_key())
    _clear_rate_limit("login-user", normalized_username)


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


def _setup_logging(app):
    if not app.debug:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)


def _validate_config(app):
    base_url = normalize_base_url(app.config.get("BASE_URL", ""))
    app.config["BASE_URL"] = base_url
    if base_url == "https://www.validadoreducabrasil.com.br":
        app.logger.warning("BASE_URL usando valor padrão. Configure para produção.")


def create_app(test_config=None):
    load_dotenv(dotenv_path="key.env")
    load_dotenv()

    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key and not test_config:
        raise RuntimeError(
            "SECRET_KEY não definida. Defina em key.env ou variável de ambiente."
        )

    app = Flask(__name__, instance_relative_config=True, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    app.config.update(
        SECRET_KEY=secret_key or "test-key-do-not-use",
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///validador_educa_brasil.sqlite3"),
        BASE_URL=os.environ.get("BASE_URL", "https://www.validadoreducabrasil.com.br"),
        DEBUG=_env_bool("DEBUG", False),
        TESTING=bool(test_config),
        TRUST_PROXY=_env_bool("TRUST_PROXY", False),
        PROXY_FIX_X_FOR=max(0, _env_int("PROXY_FIX_X_FOR", 1)),
        PROXY_FIX_X_PROTO=max(0, _env_int("PROXY_FIX_X_PROTO", 1)),
        PROXY_FIX_X_HOST=max(0, _env_int("PROXY_FIX_X_HOST", 1)),
    )

    if test_config:
        app.config.update(test_config)

    _validate_config(app)
    _setup_logging(app)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    _ensure_schema(app)

    login_manager.login_view = "admin.login"
    login_manager.login_message = "Entre como administrador para continuar."
    login_manager.login_message_category = "warning"

    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=app.config["PROXY_FIX_X_FOR"],
            x_proto=app.config["PROXY_FIX_X_PROTO"],
            x_host=app.config["PROXY_FIX_X_HOST"],
        )

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

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; img-src 'self' data:; style-src 'self'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        response.headers.pop("X-Powered-By", None)
        response.headers.pop("Server", None)
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        current_app.logger.warning(f"CSRF error: {request.remote_addr}")
        flash("Sessão expirada ou formulário inválido. Tente novamente.", "error")
        return redirect(url_for("admin.login"))

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(error):
        current_app.logger.warning(f"Upload excedeu o limite permitido: {request.remote_addr}")
        flash("O arquivo enviado excede o limite de 10 MB.", "error")
        if current_user.is_authenticated:
            return render_template(
                "admin/cadastrar_certificado.html",
                records=_available_qr_records_for_certificate(),
            ), 413
        return redirect(url_for("admin.login")), 413

    @app.errorhandler(500)
    def handle_500_error(error):
        current_app.logger.error(f"Erro interno: {error}", exc_info=True)
        flash("Erro interno do servidor. Tente novamente mais tarde.", "error")
        if current_user.is_authenticated:
            return redirect(url_for("admin.qrcodes")), 500
        return redirect(url_for("admin.login")), 500

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
            raise click.ClickException("Informe um nome de usuário válido.")

        existing = AdminUser.query.filter_by(username=username).first()
        if existing:
            raise click.ClickException("Este usuário admin já existe.")

        user = AdminUser(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Admin criado: {username}")

def _sqlite_table_columns(table_name):
    rows = db.session.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    return {row[1] for row in rows}


def _sqlite_add_column_if_missing(table_name, column_name, column_type):
    if column_name not in _sqlite_table_columns(table_name):
        db.session.execute(
            text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
        )
        return True
    return False


def _ensure_schema(app):
    with app.app_context():
        db.create_all()
        if db.engine.dialect.name != "sqlite":
            return

        changed = False
        changed |= _sqlite_add_column_if_missing("qr_records", "qr_png", "BLOB")

        if _sqlite_table_columns("certificates"):
            changed |= _sqlite_add_column_if_missing("certificates", "pdf_filename", "VARCHAR(255)")
            changed |= _sqlite_add_column_if_missing("certificates", "pdf_data", "BLOB")

        if changed:
            db.session.commit()


app = create_app()


if __name__ == "__main__":
    app.run()
