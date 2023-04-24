from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from datetime import datetime
from flask_migrate import Migrate

# Flask Instance
app = Flask(__name__)
# Add Database
#  sqlite DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# mysql db
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:scary123@localhost/our_users'

# Secret key
app.config['SECRET_KEY'] = "powertripbyjcole"
# Initialize the database
db = SQLAlchemy(app)
app.app_context().push()
migrate = Migrate(app, db, render_as_batch=True)

# Flask_Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# Create model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(160))

    @property
    def password(self):
        raise AttributeError('password is not readable')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


# create a string
def __repr__(self):
    return '<Name %r>' % self.name


@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User Deleted Successfully!!")

        our_user = Users.query.order_by(Users.date_added)
        return render_template("add_user.html",
                               form=form,
                               name=name,
                               our_user=our_user)
    except:
        flash("Whoops! There was a problem deleting user, try again...")
        return render_template("add_user.html",
                               form=form, name=name, our_user=our_user)


class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField('Password',
                                  validators=[DataRequired(), EqualTo('password_hash2', message='Password must match')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField("Submit")


@app.route("/")
def home():
    # first_name = 'John'
    return render_template('home.html')


@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(username=form.username.data, name=form.name.data, email=form.email.data,
                         password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.password_hash = ''
        flash("User added successfully")
    our_user = Users.query.order_by(Users.date_added)
    return render_template("add_user.html",
                           form=form,
                           name=name,
                           our_user=our_user)


# in bracket (first_name=first_name)

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


# Create Login page
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Successful!!")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Username or Password -- Try Again")
        else:
            flash("User dont exist")
    return render_template('login.html', form=form)


# Create Logout page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You Have Been Logged Out!")
    return redirect(url_for('login'))

# Create Dashboard page

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route("/admin")
def admin():
    return render_template('admin.html')


@app.route("/user/<name>")
def user(name):
    return render_template('user.html', name=name)


@app.route("/room_price")
def room_price():
    return render_template('room_price.html')


@app.route("/room_price/reservation")
def reservation():
    return render_template('reservation.html')


# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# Internal server error
@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500


if __name__ == "__main__":
    app.run(debug=True)
