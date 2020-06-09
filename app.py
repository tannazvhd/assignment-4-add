from flask import Flask,render_template,request,redirect, url_for,session
from mongoengine import *
from registerForm import RegisterForm
from loginForm import LoginForm
import flask_security
from flask_mongoengine import MongoEngine
import bcrypt
from flask_security import Security,MongoEngineUserDatastore, login_required,\
      UserMixin, RoleMixin
from flask_security.utils import hash_password
import re

app = Flask(__name__,template_folder="templates")
app.config['SECRET_KEY'] ='super-secret'
app.config["MONGODB_HOST"] = "mongodb://localhost:27017/Assignment4"
app.config['SECURITY_PASSWORD_SALT'] = 'this is a secret salt'
app.config["MONGODB_DB"] = True


db = MongoEngine(app)

class Role(db.Document,RoleMixin):
    name = db.StringField(max_length=80,unique=True)
    description = db.StringField(max_length=255)



class User(db.Document,UserMixin):
    firstname = db.StringField(required=True, max_length=30)
    lastname = db.StringField(required=True, max_length=30)
    dateOfBirth = db.StringField(required=True, max_length=30)
    email = db.EmailField(required=True, max_length=50)
    password = db.StringField(required=True)
    confirmpassword = db.StringField(required=True)
    active = db.BooleanField(default=True)
    confirmed_at = db.DateTimeField()
    roles=db.ListField(db.ReferenceField(Role),default=[])

user_datastore = MongoEngineUserDatastore(db,User,Role)
security = Security(app, user_datastore,register_form = RegisterForm)



@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')




@app.route('/register',methods = ['GET', 'POST'])
def register():
    form = RegisterForm() 

    if  request.method == 'POST':
        passwordtest=request.form.get("password")
        if len(passwordtest) < 6:
            return render_template('registerFail.html', msg="Make sure your password is at least 6 letters")
        elif re.search('[0-9]',passwordtest) is None:
            return render_template('registerFail.html', msg="Make sure your password has a number in it")
        elif re.search('[A-Z]',passwordtest) is None: 
            return render_template('registerFail.html', msg="Make sure your password has a capital letter in it")
        elif re.search('[a-z]',passwordtest) is None: 
            return render_template('registerFail.html', msg="Make sure your password has a small letter in it")
        else:
            existing_user = User.objects.filter(email=request.form.get("email")).first()
            if existing_user is None:
                user_datastore.create_user(  
                firstname=request.form.get("firstname"),
                lastname=request.form.get("lastname"),
                dateOfBirth=request.form.get("dateOfBirth"),
                email=request.form.get("email"),
                password=hash_password(passwordtest),
                confirmpassword = hash_password(request.form.get("confirmpassword"))
                )
                return render_template('login.html', form = form) #redirect(url_for('profile'))
            return render_template('loginFail.html')
    return render_template('register.html', form = form)



@app.route('/profile')
def profile():
    return render_template('profile.html')


@app.route('/log', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method=='POST':
        login_user = User.objects.filter(email=request.form.get("email")).first()

        if login_user:
                if flask_security.utils.verify_and_update_password(request.form.get('password'), login_user):
                    session['email'] = request.form['email']
                    return render_template('successLogin.html',firstname=login_user['firstname'],lastname=login_user['lastname'],dateOfBirth=login_user['dateOfBirth'],email=login_user['email'])#'You are logged in as ' + session['email']
        return render_template('loginFail.html')#'Invalid username/password combination' 
    return render_template('login.html', form = form)





if __name__ =='__main__':
    app.run(debug=True)