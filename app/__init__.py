"""
Flask application factory.
Creates and configures the Flask app, extensions, and blueprints.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from .config import config

# These are created here but NOT connected to any app yet.
# We connect them later inside create_app() — this pattern lets us
# create multiple app instances (e.g. for testing) without conflicts.
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_name='default'):
    """
    Application factory function.
    Creates and returns a configured Flask application instance.
    """
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    app.config.from_object(config[config_name])

    # Initialise extensions with the app
    db.init_app(app)
    csrf.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'          # where to send users who aren't logged in
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning' # controls the colour of that flash message

    # Register blueprints
    from .auth.routes import auth_bp
    from .dashboard.routes import dashboard_bp
    from .scanner.routes import scanner_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/')
    app.register_blueprint(scanner_bp, url_prefix='/scanner')

    # Register custom error handlers
    _register_error_handlers(app)

    # Auto-create all database tables on first run.
    # Safe to call every time — it skips tables that already exist.
    with app.app_context():
        db.create_all()

    return app


def _register_error_handlers(app):
    """Register custom 404 and 500 error pages."""
    from flask import render_template

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template('errors/500.html'), 500
