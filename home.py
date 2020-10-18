from flask import Flask, render_template, url_for, redirect, request, session, logging, flash, send_file, Response

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from flask_sqlalchemy import SQLAlchemy

from passlib.handlers.sha2_crypt import sha256_crypt

from datetime import timedelta

from xlsxwriter.workbook import Workbook
from flaskext.mysql import MySQL
import io
import xlwt
import pymysql

# pylint: disable = no-member

engine = create_engine("mysql+pymysql://ahmadabdelhakim@mysql-eigqttnkuk7hk:abcd1234!@mysql-eigqttnkuk7hk.mysql.database.azure.com/register")
                       #"mysql+pymysql://username:password@localhost/databasename")
# CREATE TABLE users (id SERIAL, username varchar(50), password varchar(300), PRIMARY KEY (id));
# CREATE TABLE messages (msgID SERIAL PRIMARY KEY, sender varchar(50), recipientID BIGINT UNSIGNED, message varchar(300), FOREIGN KEY (recipientID) REFERENCES users(id));

db = scoped_session(sessionmaker(bind = engine))

connection = engine.raw_connection()

app = Flask(__name__)
app.secret_key="re;isvoa;oerngv7ddo984jsrbfreaferi875a6f/r7e9/gs7/g7ser9"
app.permanent_session_lifetime = timedelta(days=7)

@app.route("/")
def index():
    return render_template("index.html")

#register form
@app.route("/register", methods =["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")   

        if password == confirm:
            secure_password = sha256_crypt.encrypt(str(password))
            db.execute("INSERT INTO users (username, password) VALUES(:username,:password)",{"username":username,"password":secure_password})
            db.commit()
            flash("Registration complete", "success")
            return redirect(url_for('login'))
        else:
            flash("Password does not match", "danger")
            return render_template("register.html")
    return render_template("register.html")

#login form
@app.route("/login", methods =["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        usernamedata = db.execute("SELECT username FROM users WHERE username=:username", {"username":username}).fetchone()
        passwordata = db.execute("SELECT password FROM users WHERE username=:username", {"username":username}).fetchone()

        if usernamedata is None:
            flash("No user is registered with this username", "danger")
            return render_template("login.html")
        else:
            for password_data in passwordata:
                if sha256_crypt.verify(password, password_data):
                    # To hide the login and register pages when logged in
                    session.permanent = True
                    session["log"] = True
                    session["loggedusername"] = username
                    flash(f"Login successful, {username}", "success")
                    return redirect(url_for('chat'))
                else:
                    flash("Incorrect password", "danger")
                    return render_template("login.html")
           
    return render_template("login.html")

                
# chat
@app.route("/chat", methods =["GET","POST"])
def chat():
    if request.method == "POST":
        username = request.form.get("username")
        message = request.form.get("message")

        usernamedata = db.execute("SELECT username FROM users WHERE username=:username", {"username":username}).fetchone()

        if usernamedata is None:
            flash("No user is registered with this username", "danger")
        else:
            if "loggedusername" in session:
                loggedusername = session["loggedusername"]
            else:
                return redirect(url_for('login'))
            sender = (db.execute("SELECT username FROM users WHERE username=:username", {"username":loggedusername}).fetchone())[0]
            recipientID = (db.execute("SELECT id FROM users WHERE username=:username", {"username":username}).fetchone())[0]
            flash(f"Your message ({message}) was sent successfully to ({username})", "success") 
            db.execute("INSERT INTO messages (sender, recipientID, message) VALUES(:sender,:recipientID,:message)",{"sender":sender,"recipientID":recipientID,"message":message})
            db.commit()

    return render_template("chat.html") 

# History
@app.route("/history")
def history():
    if "loggedusername" in session:
            loggedusername = session["loggedusername"]
    loggeduserID = (db.execute("SELECT id FROM users WHERE username=:username", {"username":loggedusername}).fetchone())[0]
    cur = connection.cursor()
    cur.execute(f"SELECT * FROM messages WHERE recipientID = {loggeduserID}")
    data = cur.fetchall()
    cur.close()
    return render_template("history.html", messages = data)

# Logout
@app.route("/logout")
def logout():
    session.clear()
    session.pop("loggedusername", None)
    flash("You are now logged out", "success")
    return redirect(url_for('login'))

#dbdump
@app.route("/dbdump")
def dbdump():
    return render_template("dbdump.html")

@app.route('/dbdump/report/excel')
def download_report():
    curr = connection.cursor()
    curr.execute("SELECT * FROM users")
    users = curr.fetchall()
    curr.close()

    cursor = connection.cursor()
    cursor.execute("SELECT * FROM messages")
    messages = cursor.fetchall()
    cursor.close()

    #output in bytes
    output = io.BytesIO()
    #create WorkBook object
    workbook = xlwt.Workbook()
    #add a sheet
    sh = workbook.add_sheet('users')
    sh2 = workbook.add_sheet('messages')
    
    #add headers
    sh.write(0, 0, 'id')
    sh.write(0, 1, 'username')
    sh.write(0, 2, 'password')
    
    i = 0
    for row in users:
        sh.write(i+1, 0, row[0])
        sh.write(i+1, 1, row[1])
        sh.write(i+1, 2, row[2])
        i += 1

    sh2.write(0, 0, 'msgID')
    sh2.write(0, 1, 'sender')
    sh2.write(0, 2, 'recipientID')
    sh2.write(0, 3, 'message')
    
    idx = 0
    for row in messages:
        sh2.write(idx+1, 0, row[0])
        sh2.write(idx+1, 1, row[1])
        sh2.write(idx+1, 2, row[2])
        sh2.write(idx+1, 3, row[3])
        idx += 1
    
    workbook.save(output)
    output.seek(0)
    
    return Response(output, mimetype="application/ms-excel", headers={"Content-Disposition":"attachment;filename=dbdump.xls"})

if __name__ == "__main__":
    app.run(debug = True)