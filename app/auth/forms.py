"""
WTForms definitions for authentication (login & registration).
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, ValidationError
)
from ..models import User


class RegistrationForm(FlaskForm):
    """Form for new user registration."""

    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required.'),
            Length(min=3, max=64, message='Username must be 3–64 characters.')
        ],
        render_kw={'placeholder': 'Choose a username', 'autocomplete': 'off'}
    )

    email = StringField(
        'Email Address',
        validators=[
            DataRequired(message='Email is required.'),
            Email(message='Enter a valid email address.')
        ],
        render_kw={'placeholder': 'you@example.com'}
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.'),
            Length(min=8, message='Password must be at least 8 characters.')
        ],
        render_kw={'placeholder': 'At least 8 characters'}
    )

    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password.'),
            EqualTo('password', message='Passwords must match.')
        ],
        render_kw={'placeholder': 'Repeat your password'}
    )

    submit = SubmitField('Create Account')

    # Custom validators — run after built-in validators
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose another.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('An account with that email already exists.')


class LoginForm(FlaskForm):
    """Form for existing user login."""

    username = StringField(
        'Username',
        validators=[DataRequired(message='Username is required.')],
        render_kw={'placeholder': 'Your username', 'autofocus': True}
    )

    password = PasswordField(
        'Password',
        validators=[DataRequired(message='Password is required.')],
        render_kw={'placeholder': 'Your password'}
    )

    remember_me = BooleanField('Remember me')

    submit = SubmitField('Log In')
