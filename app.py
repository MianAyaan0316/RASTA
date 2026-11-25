from flask import Flask, redirect, render_template, request, url_for

from config import Config
from models.database import db
from routes.auth_routes import auth_bp
from routes.web_routes import web_bp


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(web_bp)
    @app.errorhandler(404)
    def handle_not_found(error):
        if request.path == "/login":
            return render_template("login.html")
        return redirect(url_for("auth.login"))
    with app.app_context():
        db.create_all()
        if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            audit_columns = {column["name"] for column in inspector.get_columns("audits")}
            finding_columns = {column["name"] for column in inspector.get_columns("findings")}
            attack_columns = {column["name"] for column in inspector.get_columns("attack_logs")}
            if "attack_surface_json" not in audit_columns:
                db.session.execute(text("ALTER TABLE audits ADD COLUMN attack_surface_json TEXT"))
            if "file_path" not in finding_columns:
                db.session.execute(text("ALTER TABLE findings ADD COLUMN file_path VARCHAR(500)"))
            if "line_number" not in finding_columns:
                db.session.execute(text("ALTER TABLE findings ADD COLUMN line_number INTEGER"))
            for statement in (
                "ALTER TABLE attack_logs ADD COLUMN attack_name VARCHAR(120)",
                "ALTER TABLE attack_logs ADD COLUMN category VARCHAR(50)",
                "ALTER TABLE attack_logs ADD COLUMN latency_ms INTEGER",
                "ALTER TABLE attack_logs ADD COLUMN remediation TEXT",
                "ALTER TABLE attack_logs ADD COLUMN ai_response TEXT",
            ):
                column_name = statement.split(" ADD COLUMN ")[1].split()[0]
                if column_name not in attack_columns:
                    db.session.execute(text(statement))
            db.session.commit()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5050,
        debug=True,
        use_reloader=False,
    )
