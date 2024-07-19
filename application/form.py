from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length

class UploadImagePath:
    def __init__(self):
        self.path = ""

class EncryptionForm(FlaskForm):
    encryption_key = StringField('Encryption Key', validators=[DataRequired(), Length(min=16, message="Key length must be at least 16 characters")])
    submit = SubmitField('Encrypt')

class DecryptionForm(FlaskForm):
    decryption_key = StringField('Decryption Key', validators=[DataRequired(), Length(min=16, message="Key length must be at least 16 characters")])
    submit = SubmitField('Decrypt')