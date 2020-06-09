from flask_wtf import Form
from wtforms import TextField, StringField, PasswordField, SubmitField, DateField
from wtforms.validators import InputRequired, Length, EqualTo, DataRequired,ValidationError


#def validate_password(form, password):
   

class RegisterForm(Form):
    
    firstname = StringField('firstname')
    lastname = StringField('lastname')
    dateOfBirth = DateField('Date Of Birth')
    email = StringField('Email')
    # password = PasswordField('Password', validators=[
    #     DataRequired(),
    #     EqualTo('confirmpassword', message='Passwords must match'),
    #     Length(min=6,message='password must be at least 6 characters')
    # ])
    password =PasswordField('Password')
    confirmpassword = PasswordField('Repeat Password')
    submit = SubmitField('Register')


