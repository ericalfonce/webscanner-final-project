"""
Authentication routes: register, login, logout.
"""

import bcrypt
from urllib.parse import urlparse, urljoin
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from ..models import User
from .. import db, limiter
from .forms import RegistrationForm, LoginForm

auth_bp = Blueprint('auth', __name__, template_folder='../templates/auth')


def _is_safe_redirect(target):
    """Return True only if target is a relative URL on this host."""
    if not target:
        return False
    ref = urlparse(request.host_url)
    tgt = urlparse(urljoin(request.host_url, target))
    return tgt.scheme in ('http', 'https') and ref.netloc == tgt.netloc


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per 15 minutes")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = RegistrationForm()

    if form.validate_on_submit():
        password_hash = bcrypt.hashpw(
            form.password.data.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')

        user = User(
            username=form.username.data,
            email=form.email.data.lower(),
            password_hash=password_hash
        )
        db.session.add(user)
        db.session.commit()

        flash(f'Account created successfully! Welcome, {user.username}. Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form, title='Create Account')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per 15 minutes")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and bcrypt.checkpw(
            form.password.data.encode('utf-8'),
            user.password_hash.encode('utf-8')
        ):
            login_user(user, remember=form.remember_me.data)
            flash(f'Welcome back, {user.username}!', 'success')

            next_page = request.args.get('next')
            if not _is_safe_redirect(next_page):
                next_page = url_for('dashboard.index')
            return redirect(next_page)
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('auth/login.html', form=form, title='Log In')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))
