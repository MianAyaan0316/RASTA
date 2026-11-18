from flask import Flask

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
    with app.app_context():
        db.create_all()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
