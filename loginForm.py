from flask_wtf import Form
from wtforms import TextField, StringField, PasswordField, SubmitField


#
class LoginForm(Form):
    
    email = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Login')
