from flask import Flask
from flask_dropzone import Dropzone
import os


app=Flask(__name__)


app.config.from_object(__name__)

#dir_path=os.path.dirname(os.path.realpath(__file__))


app.config.update(
    #UPLOADED_PATH=os.path.join(dir_path,"static/uploaded_files"),
    DROPEZONE_ALLOWED_FILE_TYPE='image',
    DROPZONE_MAX_FILE_SIZE=50,
    DROPZONE_MAX_FILES=1
)


dropzone = Dropzone(app)
from application import routes

