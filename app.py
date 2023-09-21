from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import jsonify

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ein_sehr_geheimer_schlüssel'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Hallo1211@/database?unix_socket=/cloudsql/kontaktv:europe-west6:database'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.before_first_request
def create_tables():
    db.create_all()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(150), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Benutzername', validators=[DataRequired()])
    password = PasswordField('Passwort', validators=[DataRequired()])
    submit = SubmitField('Einloggen')

class RegistrationForm(FlaskForm):
    email = StringField('E-Mail Adresse', validators=[DataRequired()])
    username = StringField('Benutzername', validators=[DataRequired()])
    password = PasswordField('Passwort', validators=[DataRequired()])
    password_confirm = PasswordField('Passwort bestätigen', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrieren')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Dieser Benutzername ist bereits vergeben. Bitte wählen Sie einen anderen.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Diese E-Mail Adresse wird bereits verwendet. Bitte verwenden Sie eine andere.')

@app.route('/')
@login_required
def contact_list():
    contacts = Contact.query.order_by(Contact.name).all()
    return render_template('contact_list.html', contacts=contacts)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        new_contact = Contact(name=name, phone=phone, email=email)
        db.session.add(new_contact)
        db.session.commit()
        flash('Kontakt erfolgreich hinzugefügt!', 'success')
        return redirect(url_for('contact_list'))
    return render_template('add_contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('contact_list'))
            else:
                error = 'Falsches Passwort.'
        else:
            error = 'Benutzername existiert nicht.'
    return render_template('login.html', form=form, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_pw, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Erfolgreich registriert! Sie können sich jetzt anmelden.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sie wurden erfolgreich abgemeldet.', 'success')
    return redirect(url_for('login'))

@app.route('/api/contacts', methods=['GET'])
@login_required
def get_contacts():
    contacts = Contact.query.order_by(Contact.name).all()
    return jsonify([{'id': contact.id, 'name': contact.name, 'phone': contact.phone, 'email': contact.email} for contact in contacts])


if __name__ == '__main__':
    app.run(debug=True)
