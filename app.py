from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import CreateUserForm, LoginUserForm, FeedbackForm, DeleteForm
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Unauthorized

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

@app.route('/logout')
def logout():
    session.pop('username')
    flash("You have logged out", "success")
    return redirect("/")


@app.route('/users/<username>')
def show_secret(username):
   
    if 'username' not in session:
        flash("Please login first", 'danger')
        return redirect('/login')
    user = User.query.get_or_404(username)
    form = DeleteForm()
    return render_template('user_info.html', user=user, form=form)

@app.route('/users/<username>/delete', methods=["POST"])
def delete_user(username):
    if "username" not in session or username != session['username']:
        raise Unauthorized()
    
    user = User.query.get(username)
    Feedback.query.filter_by(username=username).delete()
    db.session.delete(user)
    
    db.session.commit()
    session.pop("username")

    return redirect('/login')

@app.route('/users/<username>/feedback/add', methods=["POST", "GET"])
def get_feedback(username):
    
    if "username" not in session or username != session['username']:
        raise Unauthorized()
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        feedback = Feedback(title=title, content=content, username=username)
        db.session.add(feedback)
        db.session.commit()
        return redirect(f"/users/{feedback.username}")
    else: 
        return render_template('feedback.html', form=form)


@app.route('/feedback/<int:id>/update', methods=["POST", "GET"])
def update_feedback(id):
    feedback = Feedback.query.get(id)

    if "username" not in session or feedback.username != session['username']:
        raise Unauthorized()

    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data

        db.session.commit()

        return redirect(f"/users/{feedback.username}")
        
    return render_template("edit_feedback.html", form=form)
    


@app.route('/feedback/<int:id>/delete', methods=["POST"])
def delete_feedback(id):
    feedback = Feedback.query.get(id)
    username = feedback.username
    if "username" not in session or username != session['username']:
        raise Unauthorized()

    
    db.session.delete(feedback)
    db.session.commit()
    return redirect(f'/users/{feedback.username}')


