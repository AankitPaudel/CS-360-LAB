from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql://root:@localhost/lab66'
app.config['SECRET_KEY'] = 'your_secret_key_here'
db = SQLAlchemy(app)



@app.route('/')
def index():
    return render_template('index.html')


# Model 
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            hashed_password = generate_password_hash(request.form.get('password'))
            new_user = Users(
                first_name=request.form.get('first_name'),
                last_name=request.form.get('last_name'),
                email=request.form.get('email'),
                phone_number=request.form.get('phone'),
                password_hash=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Email already registered or error in registration.')
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Users.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id  # Log the user in
            return redirect(url_for('dashboard'))
        else:
            # Instead of just flashing a message
            flash('Invalid email or password.') 
            return redirect(url_for('login', error='credentials'))
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to view this page.')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = Users.query.get(user_id)
    if user:
        return render_template('dashboard.html', first_name=user.first_name, last_name=user.last_name)
    else:
        # Handle case where user is not found
        flash('User not found.')
        return redirect(url_for('login'))



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)
