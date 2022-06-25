
# _______________________________Thêm thư viện___________________________________________________________

from flask import Flask, render_template, Response, request, redirect, flash
import cv2
import threading
import base64
from flask_login.utils import login_user, logout_user
from flask_socketio import SocketIO,emit
import jsonpickle
import imagezmq
from flask_sqlalchemy import SQLAlchemy
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask_login import LoginManager, UserMixin  
import hashlib

# _______________________________Khai báo__________________________________________________________________

app = Flask(__name__)
app.config['SECRET_KEY'] = '8f42a73054b1749f8f58848be5e6502c'
#login
login = LoginManager(app=app)
#Stream
socketio = SocketIO(app,async_mode='threading')
countConnect = 0
imageRecv = imagezmq.ImageHub(open_port = 'tcp://127.0.0.1:1998',REQ_REP= False)
#Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///video.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
user = None

class Video(db.Model):
    ten = db.Column(db.String(50), primary_key=True)
    thoigian = db.Column(db.String(20), nullable=False)
    mahoa = db.Column(db.String(2), nullable=False)

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key = True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role
#db.create_all()
keyAES = b'Sixteen byte key'

# ______________________________API_______________________________________________________________________
#Login
@login.user_loader
def user_load(user_id):
    return User.query.get(user_id)

@app.route('/login', methods = ["POST"])
def login():
      global user
      username = request.form.get("username")
      password = str(request.form.get("password"))
      password = str(hashlib.md5(password.strip().encode("utf-8")).hexdigest())
      user = User.query.filter(User.username == username, User.password == password).first()
      if user:
          login_user(user=user)
          return redirect("/api/streaming")
      else:
          flash('Sai tài khoản hoặc mật khẩu. Vui lòng đăng nhập lại', 'danger')
          return redirect("/")
          
@app.route('/logout')
def logout():
    logout_user()
    return redirect("/") 

@app.route('/admin')
def admingg():
    global user
    users = User.query.all()
    return render_template('admin.html',role = user.role, users = users)       

@app.route('/deleteuser/<int:id>')
def deleteuser(id):
    global user
    User.query.filter_by(id=id).delete()
    db.session.commit()
    users = User.query.all()
    return render_template('admin.html',role = user.role, users = users)   

@app.route('/register', methods = ["POST"])
def register():
    global user
    username = request.form.get("username")
    password = str(request.form.get("password"))
    password = str(hashlib.md5(password.strip().encode("utf-8")).hexdigest())
    role = request.form.get("role")
    re = User(username,password,role)
    db.session.add(re)
    db.session.commit()
    users = User.query.all()
    return render_template('admin.html',role = user.role, users = users)
#App
@app.route('/')
def index():
    global user
    if user != None:
        return render_template('index.html',role=user.role)
    else:    
        return render_template('index.html',role='nomarl')

@app.route('/api/streaming')
def streaming():
    global user
    if user != None:
        return render_template('videostream.html',role=user.role)
    else:    
        return render_template('videostream.html',role='nomarl')

@app.route('/api/videoplayback')
def videoplayback():
    global user
    if user != None:
        videos = Video.query.filter_by(mahoa='1')
        return render_template('videoplayback.html',role=user.role,videos=videos)
    else:
        videos = Video.query.filter_by(mahoa='1')
        return render_template('videoplayback.html',role='normal',videos=videos)   

@app.route('/api/rsa', methods=['POST'])
def rsa():
    global keyAES
    data = request.data
    pubKey = RSA.importKey(data)
    rsa_public_key = PKCS1_OAEP.new(pubKey)
    aesKey = rsa_public_key.encrypt(keyAES)
    response = {'key': "{}".format(aesKey)}
    response_pickled = jsonpickle.encode(response)
    return Response(response=response_pickled, status=200, mimetype="application/json")

@app.route('/api/getVideo/<string:name>',methods=['GET','POST'])
def getVideo(name):
    global cipherDecrypto
    videoDir = "static/video/{}".format(name)
    try:
        with open(videoDir,'rb') as f:
            data = f.read()
            iv = data[:AES.block_size]
            cipherDecrypto = AES.new(keyAES, AES.MODE_CBC, iv)
            videoDecrypt = unpad(cipherDecrypto.decrypt(data[AES.block_size:]), AES.block_size)
            return base64.b64encode(videoDecrypt).decode('ascii')
    except IOError:
        print("File not accessible")

#SocketIO
#Nếu có client connect
@socketio.on('connect')
def connectChannel():
    global countConnect
    countConnect+=1
#Nếu client disconnect
@socketio.on('disconnect')
def disconnectChannel():
    global countConnect
    if countConnect >0:
        countConnect-=1
    elif countConnect<0:
        countConnect=0

# _______________________________Funtion_________________________________________________________________

def thSendImg():
    global countConnect
    while True:
    	#nhận hình ảnh từ Yolo
    	msg,img = imageRecv.recv_image()
    	#encode ảnh
    	_,img_encode = cv2.imencode('.jpg',img)
    	#encode base64
    	img_64 = base64.b64encode(img_encode).decode('ascii')
    	#Nếu có client connect thì gửi ảnh
    	if countConnect>0 :
    		socketio.emit('imgChannel', {'data': img_64}, broadcast=True)
# _______________________________Main()__________________________________________________________________

if __name__ == '__main__':
    threading.Thread(target=thSendImg, daemon=True).start()
    socketio.run(app,host='0.0.0.0',port=5000)


