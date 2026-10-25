import os, pytest, secrets, app as appmod
def test_production_requires_secret_key(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNTRACK_ENV", "production"); monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"): appmod.create_app({"DB_PATH": str(tmp_path / "p.db")})
def test_short_secret_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "short")
    with pytest.raises(RuntimeError, match="32"): appmod.create_app({"DB_PATH": str(tmp_path / "p.db")})
def test_production_cookie_and_hsts(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNTRACK_ENV", "production"); monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    a = appmod.create_app({"DB_PATH": str(tmp_path / "p.db")}); assert a.config["SESSION_COOKIE_SECURE"] is True
    assert "max-age" in a.test_client().get("/health").headers["Strict-Transport-Security"]
def test_dev_secret_file_is_private_and_not_in_db_dir_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False); monkeypatch.delenv("VULNTRACK_ENV", raising=False)
    appmod.create_app({"DB_PATH": str(tmp_path / "d.db")}); f = tmp_path / "d.db.secret"; assert f.exists() and oct(f.stat().st_mode)[-3:] == "600"
def test_bootstrap_admin_from_env_and_no_default_users(tmp_path, monkeypatch):
    pw = secrets.token_urlsafe(16); monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32)); monkeypatch.setenv("INITIAL_ADMIN_USERNAME", "root1"); monkeypatch.setenv("INITIAL_ADMIN_PASSWORD", pw)
    a = appmod.create_app({"DB_PATH": str(tmp_path / "b.db")}); c = a.test_client(); t = c.get("/api/auth/me").get_json()["csrf"]
    assert c.post("/api/auth/login", json={"username": "root1", "password": pw}, headers={"X-CSRF-Token": t}).status_code == 200
def test_empty_install_has_no_users(tmp_path, monkeypatch):
    for k in ("INITIAL_ADMIN_USERNAME", "INITIAL_ADMIN_PASSWORD"): monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32)); import db; appmod.create_app({"DB_PATH": str(tmp_path / "n.db")})
    assert db.connect(str(tmp_path / "n.db")).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
def test_weak_bootstrap_password_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32)); monkeypatch.setenv("INITIAL_ADMIN_USERNAME", "root1"); monkeypatch.setenv("INITIAL_ADMIN_PASSWORD", "short")
    import db; appmod.create_app({"DB_PATH": str(tmp_path / "w.db")}); assert db.connect(str(tmp_path / "w.db")).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
def test_backup_and_restore_roundtrip(tmp_path, monkeypatch):
    import manage, db
    monkeypatch.setenv("DB_PATH", str(tmp_path / "x.db")); c = db.migrate(str(tmp_path / "x.db")); c.execute("INSERT INTO settings VALUES('probe','1')"); c.close()
    manage.cmd_backup(str(tmp_path / "bk.db")); c = db.connect(str(tmp_path / "x.db")); c.execute("DELETE FROM settings WHERE key='probe'"); c.close()
    manage.cmd_restore(str(tmp_path / "bk.db")); assert db.connect(str(tmp_path / "x.db")).execute("SELECT value FROM settings WHERE key='probe'").fetchone()[0] == "1"
