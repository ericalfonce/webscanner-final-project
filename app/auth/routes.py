"""
Authentication routes: register, login, logout.
"""

import bcrypt
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from ..models import User
from .. import db
from .forms import RegistrationForm, LoginForm

auth_bp = Blueprint('auth', __name__, template_folder='../templates/auth')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handle new user registration."""
    # Redirect already-logged-in users
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = RegistrationForm()

    if form.validate_on_submit():
        # Hash password with bcrypt (cost factor 12)
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
def login():
    """Handle user login."""
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

            # Redirect to the page the user originally tried to access
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('auth/login.html', form=form, title='Log In')


@auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))
