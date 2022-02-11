## Package import and setup
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json 
from hashlib import sha256

## Project specific Confrigration

with open("info.json", "r") as c:
    parameters = json.load(c)["parameters"]


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = parameters["database"]
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = parameters["track_modifications"]
app.config['SECRET_KEY'] = parameters["secret_key"] 

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

## Database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(512), nullable = False)
    password = db.Column(db.String(512), nullable = False)

    def __repr__(self):
        return str(self.id) + ' :Name: ' + str(self.name)

class Blockchain(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    desc_transfer = db.Column(db.String(512), nullable = False)
    prev_hash = db.Column(db.String(512), nullable = False)
    sender_id = db.Column(db.String(512), nullable = False)
    reciver_id = db.Column(db.String(512), nullable = False)
    transaction_amt = db.Column(db.Float, nullable = False)
    new_hash = db.Column(db.String(512), nullable = False)
    nonce = db.Column(db.String(512), nullable = False)
    
    def __repr__(self):
        return str(self.id) + ': New Hash: ' + self.new_hash


class Tnx(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    desc_transfer = db.Column(db.String(256), nullable=False)
    transaction_amt = db.Column(db.String(512), nullable=False)
    sender_id = db.Column(db.String(512), nullable=False)
    reciver_id = db.Column(db.String(512), nullable=False)

    def __repr__(self):
        return str(self.id) + ':Tnx Type ' + self.desc_transfer
    

## Fundamental Functions
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

def SHA256(text):
    return sha256(text.encode("ascii")).hexdigest()


def mine(prev_hash, item, difficulty):
    prefix_str = '0'*difficulty
    for nonce in range(100000000000):
        text = str(prev_hash) + str(item.sender_id) + str(item.reciver_id) + str(item.transaction_amt) + str(nonce)
        new_hash = SHA256(text)
        print(new_hash)
        if new_hash.startswith(prefix_str):
            return new_hash, nonce
    raise BaseException(f"Couldn't find correct has after trying 100000000000 times")


## routes
@app.route('/', methods = ['GET', 'POST'])
def index():
    blocks, tnxs = Blockchain.query.all(), Tnx.query.all()
    return render_template('index.html', blocks = blocks, tnxs = tnxs)

## Authentication and User Setup
@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        password =  SHA256(password)
        pos_users = User.query.filter_by(name = name)
        
        for i in pos_users:
            if i.name == name and i.password == password:
                user = User.query.get(i.id)
                load_user(user.id)
                login_user(user)
                return render_template('index.html', current_user = current_user, msg = "Logged in")

    return render_template('login.html')


@app.route('/signout', methods = ['GET', 'POST'])
@login_required
def signout():
    logout_user()
    return redirect(url_for('login'))



@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        password = SHA256(password)
        
        new_user = User(name = name, password = password)
        db.session.add(new_user)
        db.session.commit()
        
        pos_users = User.query.filter_by(name = name)
        
        for i in pos_users:
            if i.name == name and i.password == password:
                user = User.query.get(i.id)
                load_user(user.id)
                login_user(user)
                return render_template('login.html', msg = "Account create", current_user = current_user)
            
    return render_template('login.html')
                

## Tnxs
@app.route('/makepayment', methods = ['GET', 'POST'])
@login_required
def makepayment():
    if request.method == 'POST':
        desc_transfer = request.form.get('desc_transfer')
        transaction_amt = request.form.get('transaction_amt')
        reciver_id = request.form.get('reciver_id')
        password = request.form.get('password')
        password = SHA256(password)
        if current_user.password == password:
            tnx_block = Tnx(desc_transfer = str(desc_transfer), transaction_amt = str(transaction_amt), sender_id = str(current_user.id), reciver_id = str(reciver_id))
            db.session.add(tnx_block)
            db.session.commit()
            return render_template('index.html', current_user = current_user, msg = "Payment Successfully!!")
    return render_template('index.html', current_user = current_user)



@app.route('/blockchain', methods = ['GET', 'POST'])
@login_required
def blockchain():
    item = Tnx.query.all()[-1]
    block = Blockchain.query.all()[-1]
    difficulty = 2
    if len(item) == 1:
        prev_hash = "0x9109C4575a824535bAc4efA008Ed4E81DFf8755E"
    else:
        prev_hash = block.new_hash
        
    new_hash, nonce = mine(prev_hash, item, difficulty)
    
    block = Blockchain(desc_transfer = item.desc_transfer, prev_hash = prev_hash, sender_id = item.sender_id, reciver_id = item.reciver_id, transaction_amt = item.transaction_amt, new_hash = new_hash, nonce = nonce)
    db.session.add(block)
    db.session.commit()
    
    return render_template('index.html', current_user = current_user, msg = "Block Mined")


@app.route('/mineonclient/<int:num>', methods = ['GET', 'POST'])
@login_required
def mineonclient(num):
    return render_template('index.html', current_user = current_user, num = num)


@app.route('/mine')
@login_required
def mine_add():
    print(request.get_json())
    return 'Sucesss', 200
    
        
if __name__ == '__main__':
    app.run(debug = True, threaded = True)