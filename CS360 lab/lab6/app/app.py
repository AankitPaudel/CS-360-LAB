from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
import os


# Initialize the Flask application
app = Flask(__name__)
app.config.from_pyfile('config.py')  # Load configuration from a separate file

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)

# Import models and routes after extension initialization to avoid circular imports
from models import User  # Assuming models.py contains User and other models
import routes  # Assuming routes.py contains view functions

if __name__ == '__main__':
    app.run(debug=True, port=5001)
