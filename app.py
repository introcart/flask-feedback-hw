from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import CreateUserForm, LoginUserForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgres:///feedbackdb_"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def go_home():
    return redirect('/register')

@app.route('/register', methods=["POST", "GET"])
def sign_up():
    form = CreateUserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data 
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username, password, email, first_name, last_name)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append("Username taken.  Please pick another")
            return render_template('register.html', form=form)
        session["username"]=new_user.username
        flash("Welcome!  Successfully Created Your Account!", "success")
        return redirect(f'/users/{new_user.username}')
    return render_template("register.html", form=form)

@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginUserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.authenticate(username,password)
        if user:
            flash(f"Welcome Back", "success")
            session["username"]=user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ["Invalid username/password"]
    return render_template('login.html', form=form)

@app.route(f'/users/<username>')
def show_secret(username):
    user = User.query.get_or_404(username)
    if 'username' not in session:
        flash("Please login first", 'danger')
        return redirect('/login')
    return render_template('user_info.html', user=user)

@app.route('/logout')
def logout():
    session.pop('username')
    flash("You have logged out", "success")
    return redirect("/")



