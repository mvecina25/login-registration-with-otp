from flask import Flask, render_template, url_for, redirect, session, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os
import random
import string

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# Set app configuration using environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True

# Set app configuration using environment variables
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    otp = db.Column(db.String(6), nullable=True)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    email = StringField(validators=[
        InputRequired(), Length(max=120)], render_kw={"placeholder": "Email"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email address is already registered. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class OTPForm(FlaskForm):
    otp = StringField(validators=[
        InputRequired(), Length(min=6, max=6)], render_kw={"placeholder": "OTP"})

    submit = SubmitField('Verify OTP')


def generate_otp():
    digits = string.digits
    return ''.join(random.choice(digits) for _ in range(6))


def send_email(to, otp):
    subject = 'Email OTP Verification'
    sender = app.config['MAIL_USERNAME']
    recipients = [to]
    body = f"Your One Time Passcode is: <h2><strong>{otp}</strong></h2>"
    msg = Message(subject=subject, sender=sender, recipients=recipients, html=body)
    mail.send(msg)


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                session['user_id'] = user.id
                return redirect(url_for('verify_login_otp'))
            else:
                flash('Invalid username or password. Please try again.')
        else:
            flash('Invalid username or password. Please try again.')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id

        return redirect(url_for('verify_register_otp'))

    return render_template('register.html', form=form)


@app.route('/verify-login-otp', methods=['GET', 'POST'])
def verify_login_otp():
    form = OTPForm()
    if request.method == 'POST':
        if 'verify_otp' in request.form:
            user_id = session.get('user_id')
            user = User.query.get(user_id)

            if user and str(user.otp) == form.otp.data:
                session.pop('user_id')
                user.otp = None
                db.session.commit()
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid OTP. Please try again.')

        elif 'generate_otp' in request.form:
            user_id = session.get('user_id')
            user = User.query.get(user_id)

            if user:
                otp = generate_otp()
                user.otp = otp
                db.session.commit()

                # Send email with OTP code
                send_email(user.email, otp)

                flash('OTP has been generated and sent to your email.')
            else:
                flash('Failed to generate OTP. User not found.')

        elif request.method == 'GET':
            if current_user.is_authenticated:
                return redirect(url_for('dashboard'))
            else:
                flash('Please log in to verify your OTP.')

    return render_template('verify_login_otp.html', form=form)


@app.route('/verify-register-otp', methods=['GET', 'POST'])
def verify_register_otp():
    form = OTPForm()
    if request.method == 'POST':
        if 'verify_otp' in request.form:
            user_id = session.get('user_id')
            user = User.query.get(user_id)

            if user and str(user.otp) == form.otp.data:
                session.pop('user_id')
                user.otp = None
                db.session.commit()
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid OTP. Please try again.')

        elif 'generate_otp' in request.form:
            user_id = session.get('user_id')
            user = User.query.get(user_id)

            if user:
                otp = generate_otp()
                user.otp = otp
                db.session.commit()

                # Send email with OTP code
                send_email(user.email, otp)

                flash('OTP has been generated and sent to your email.')
            else:
                flash('Failed to generate OTP. User not found.')

        elif request.method == 'GET':
            if current_user.is_authenticated:
                return redirect(url_for('dashboard'))
            else:
                flash('Please log in to verify your OTP.')                

    return render_template('verify_login_otp.html', form=form)


@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email
        })
    else:
        return jsonify({'error': 'User not found'}), 404

########## API ##########

@app.route('/api/generate-otp', methods=['POST'])
@login_required
def generate_otp_api():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if user:
        if bcrypt.check_password_hash(user.password, password):
            otp = generate_otp()
            user.otp = otp
            db.session.commit()

            return {'otp': otp}, 200
        else:
            return {'message': 'Invalid username or password'}, 401
    else:
        return {'message': 'User not found'}, 404
    

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    otp = data.get('otp')

    user = User.query.filter_by(username=username).first()

    if user:
        if bcrypt.check_password_hash(user.password, password):
            if str(user.otp) == otp:
                user.otp = None
                db.session.commit()
                login_user(user)
                return {'message': 'Login successful'}, 200
            else:
                return {'message': 'Invalid OTP'}, 401
        else:
            return {'message': 'Invalid username or password'}, 401
    else:
        return {'message': 'User not found'}, 404


if __name__ == "__main__":
    app.run(debug=True)
