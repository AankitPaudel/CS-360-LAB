from flask import Flask, jsonify, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/lab66'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)  
    password_hash = db.Column(db.String(255), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


def create_tables():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            # Return a JSON response indicating success
            return jsonify({'success': True})
        else:
            # Return a JSON response indicating an error
            return jsonify({'error': 'Incorrect password or credentials.'}), 401

    # If it's a GET request, 
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        existing_user = User.query.filter_by(email=request.form['email']).first()
        if existing_user is None:
            user = User(
                first_name=request.form['first_name'],
                last_name=request.form['last_name'],
                email=request.form['email'],
                phone=request.form['phone'],
                password_hash=generate_password_hash(request.form['password'])
            )
            db.session.add(user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email already registered.', 'warning')
            return render_template('register.html', email=request.form['email'])

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    
    # Using session to get the user object
    user_id = session['user_id']
    user = db.session.get(User, user_id)  # Updated to use Session.get()

    if user:
        return render_template('dashboard.html', first_name=user.first_name, last_name=user.last_name)
    else:
        flash('User not found.', 'warning')
        return redirect(url_for('login'))
    

@app.route('/users')
def users():
    users = User.query.all()  # Get all users
    user_data = [{'first_name': user.first_name, 'last_name': user.last_name, 'email': user.email} for user in users]
    return jsonify(user_data)



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You were successfully logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
