"""
WebScanner - Educational Web Vulnerability Scanner
Entry point for the Flask application.
Run with: python run.py
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(
        debug=True,       # shows detailed error pages — turn OFF in production
        host='127.0.0.1', # only accessible from this machine (not the whole network)
        port=5000
    )
