from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from models.database import User, db


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, request.form.get("password", "")):
            session["user_id"] = user.id
            return redirect(url_for("web.dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not email or not password:
            flash("Username, email, and password are required.", "error")
        elif User.query.filter_by(email=email).first():
            flash("That email is already registered.", "error")
        else:
            user = User(username=username, email=email, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            session["user_id"] = user.id
            return redirect(url_for("web.dashboard"))
    return render_template("login.html", register_mode=True)


@auth_bp.route("/demo-login")
def demo_login():
    user = User.query.filter_by(email="demo@rastashield.local").first()
    if not user:
        user = User(username="demo", email="demo@rastashield.local", password_hash=generate_password_hash("demo"))
        db.session.add(user)
        db.session.commit()
    session["user_id"] = user.id
    return redirect(url_for("web.dashboard"))


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
