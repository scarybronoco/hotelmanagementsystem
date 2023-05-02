from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from webforms import LoginForm, AdminForm, UserForm, PostForm
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, EqualTo
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
bcrypt = Bcrypt(app)

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


class AdminSignup(db.Model, UserMixin):
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


class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Title = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    nationality = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    type_of_room = db.Column(db.String(100), nullable=False)
    Bedding_Type = db.Column(db.String(100), nullable=False)
    Number_of_rooms = db.Column(db.String(100), nullable=False)
    check_in = db.Column(db.String(100), nullable=False)
    check_out = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return '<Name %r>' % self.username


# db.create_all()

# insert data one time
# admin = Admin(username='scary123', password=bcrypt.generate_password_hash('scarybronco', 20))
# db.session.add(admin)
# db.session.commit()



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








@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.username = request.form['username']
        name_to_update.email = request.form['email']
        try:
            db.session.commit()
            flash("User Updated Succesfully")
            return render_template("update.html", form=form, name_to_update=name_to_update)
        except:
            flash("Error! Try again.")
            return render_template("update.html", form=form, name_to_update=name_to_update)
    else:
        return render_template("update.html", form=form, name_to_update=name_to_update)


@app.route("/")
def home():
    return render_template('home.html')


# in bracket (first_name=first_name)




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
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("dashboard.html",
                                   form=form,
                                   name_to_update=name_to_update)
        except:
            flash("Error!  Looks like there was a problem...try again!")
            return render_template("dashboard.html",
                                   form=form,
                                   name_to_update=name_to_update)
    return render_template('dashboard.html', form=form, name_to_update=name_to_update)


@app.route("/user/<name>")
def user(name):
    return render_template('user.html', name=name)


@app.route("/room_price")
def room_price():
    return render_template('room_price.html')


@app.route('/admin/', methods=['GET', 'POST'])
def adminLogin():
    form = LoginForm()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == '' and password == '':
            flash('please fill the form')
            return redirect('/admin/')
        else:
            admin = Admin().query.filter_by(username=username).first()
            if admin and bcrypt.check_password_hash(admin.password, password):
                session['admin_id'] = admin.id
                session['admin_name'] = admin.username
                flash('Login Successfully')
                return redirect('/admin/index')
            else:
                flash('Invalid username or password')
                return redirect('/admin/')

    else:
        return render_template('admin/login.html', title="Admin login", form=form)


@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if session.get('admin_id'):
        session['admin_id'] = None
        session['admin_name'] = None
        return redirect('/')


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


@app.route("/room_price/reservation", methods=['GET', 'POST'])
@login_required
def reservation():
    form = PostForm()
    if request.method == 'POST':
        # process the form data and save to the database
        Title = request.form.get('Title')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        nationality = request.form.get('nationality')
        phone = request.form.get('phone')
        type_of_room = request.form.get('type_of_room')
        Bedding_Type = request.form.get('Bedding_Type')
        Number_of_rooms = request.form.get('Number_of_rooms')
        check_in = request.form.get('check_in')
        check_out = request.form.get('check_out')

        if Title == '' or first_name == '' or last_name == '' or email == '' or nationality == '' or phone == '' or type_of_room == '' or Bedding_Type == '' or Number_of_rooms == '' or check_in == '' or check_out == '':
            flash('Please fill all the field')
            return redirect('/room_price/reservation')
        else:
            reserve = Reservation(Title=Title, first_name=first_name, last_name=last_name,
                                  email=email, nationality=nationality, phone=phone,
                                  type_of_room=type_of_room, Bedding_Type=Bedding_Type,
                                  Number_of_rooms=Number_of_rooms, check_in=check_in,
                                  check_out=check_out)
            db.session.add(reserve)
            db.session.commit()
            flash('Booking successful')
            return redirect('/room_price/reservation')
    else:
        # display the form
        return render_template('reservation.html', form=form)


@app.route('/admin/index', methods=['GET', 'POST'])
def adminGet():
    reservee = Reservation.query.all()
    return render_template('/admin/index.html', reservee=reservee)


@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')
    Reservation().query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    flash('Approve Successfully')
    return redirect('/admin/index')


# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# Internal server error
@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500


if __name__ == "__main__":
    app.run(debug=False)
