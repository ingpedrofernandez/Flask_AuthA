import cur
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import sqlite3 as sql
import psycopg
import psycopg2
import gunicorn
import os
from dotenv import load_dotenv
import requests
from urllib.parse import urlparse
from urllib.parse import parse_qs
import platform

#pip freeze > requirements.txt
#psycopg==3.2.5
#

app = Flask(__name__)
app.config['SECRET_KEY'] = "kira"

# CREATE DATABASE


class Base(DeclarativeBase):
    pass


#app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///flask_auth4.db"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://flask_auth4_user:kbPqCVYweByhsgKzNVeBjfgSCuvllEos@dpg-cv6fvibqf0us73f2lao0-a/flask_auth4"

db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Roleuser, user_id)


# CREATE TABLE
class Roleuser(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(1000))
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    imagelink: Mapped[str] = mapped_column(String(1000))
    role: Mapped[str] = mapped_column(String(50))

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(1000))
    mobile: Mapped[int] = mapped_column(Integer)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    imagelink: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route("/return_home/<string:name>, <string:role>", methods=['POST', 'GET'])
def return_home(name,role):
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()
    return render_template("return_index.html", name=name, role=role, logged_in=current_user.is_authenticated, users=user)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        email = request.form.get('email')
        result = db.session.execute(db.select(Roleuser).where(Roleuser.email == email))

        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        destination_path = ""
        fileobj = request.files['file']
        file_extensions = ["JPG", "JPEG", "PNG", "GIF"]
        uploaded_file_extension = fileobj.filename.split(".")[1]
        # validating file extension
        if (uploaded_file_extension.upper() in file_extensions):
            destination_path = f"static/uploads_roles/{fileobj.filename}"
            fileobj.save(destination_path)

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )

        if email == "ingpedro1007@gmail.com":
            new_user = Roleuser(
              email=request.form.get('email'),
              password=hash_and_salted_password,
              name=request.form.get('name'),
              imagelink=destination_path,
              role='admin'
              )

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("admin"))
        else:
            new_user = Roleuser(
                email=request.form.get('email'),
                password=hash_and_salted_password,
                name=request.form.get('name'),
                imagelink=destination_path,
                role=request.form.get('role')

            )

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("user"))




    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        con = sql.connect("instance/flask_auth4.db")
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("select * from roleuser where email=?", (email,))
        data = cur.fetchone()

        result = db.session.execute(db.select(Roleuser).where(Roleuser.email == email))
        user = result.scalar()

        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))

        else:
            if user.role == 'admin':
                print(user.imagelink)
                photo=user.imagelink
                login_user(user)
                return redirect(url_for('admin', photo=photo))
            else:
                login_user(user)
                return redirect(url_for('user'))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/admin')
@login_required
def admin():
    print(current_user.email)
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()
    return render_template("admin.html", name=current_user.email, role=current_user.role, logged_in=True, users=user)

@app.route('/user')
@login_required
def user():
    print(current_user.email)
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()
    return render_template("user.html", name=current_user.email, role=current_user.role, logged_in=True, users=user)

@app.route('/users')
@login_required
def users():
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()

    con = sql.connect("instance/flask_auth4.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from user")
    data = cur.fetchall()
    return render_template("users.html", name=current_user.email, role=current_user.role, logged_in=True, users=user, datas=data)

@app.route('/role_users')
@login_required
def role_users():
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()

    con = sql.connect("instance/flask_auth4.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from roleuser")
    data = cur.fetchall()
    return render_template("role_users.html", name=current_user.email, role=current_user.role, logged_in=True, users=user, datas=data)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():

    # return send_from_directory('/static/files/', 'cheat_sheet.pdf')
    return send_from_directory('static', path="files/cheat_sheet.pdf")


@app.route("/show_user/<string:id>, <string:name>, <string:role>", methods=['POST', 'GET'])
def show_user(id,name,role):
    #url = 'http://127.0.0.1:5000/edit_user/1?name=ingpedro1007@gmail.com&role=admin'
    #parsed_url = urlparse(url)
    #name = parse_qs(parsed_url.query)['name'][0]
    #role = parse_qs(parsed_url.query)['role'][0]
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()

    con = sql.connect("instance/flask_auth4.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from user where id=?", (id,))
    data = cur.fetchone()
    return render_template("show_user.html", name=name, role=role, users=user, datas=data)


@app.route("/add_user/<string:name>, <string:role>", methods=['POST', 'GET'])
def add_user(name, role):
    #url = 'http://127.0.0.1:5000/edit_user/1?name=ingpedro1007@gmail.com&role=admin'
    #parsed_url = urlparse(url)
    #name = parse_qs(parsed_url.query)['name'][0]
    #role = parse_qs(parsed_url.query)['role'][0]
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()



    if request.method == 'POST':
        name = request.form['name']
        mobile = request.form['mobile']
        email = request.form['email']

        destination_path2 = ""
        fileobj = request.files['file']
        file_extensions = ["JPG", "JPEG", "PNG", "GIF"]
        uploaded_file_extension = fileobj.filename.split(".")[1]
        # validating file extension
        if (uploaded_file_extension.upper() in file_extensions):
            destination_path2 = f"static/uploads/{fileobj.filename}"
            fileobj.save(destination_path2)

            new_user = User(
                name=request.form.get('name'),
                mobile=request.form.get('mobile'),
                email=request.form.get('email'),
                imagelink=destination_path2
            )

            db.session.add(new_user)
            db.session.commit()

            #con = sql.connect("instance/flask_auth4.db")
            #cur = con.cursor()
            #cur.execute("insert into user(name,mobile,email,imagelink) values (?,?,?,?)",
                #        (name, mobile, email, destination_path))
            #con.commit()
            flash('User Added', 'success')
            return redirect(url_for("users"))

        else:
            flash('only images are accepted', 'danger')
            return redirect(url_for("users"))

    return render_template("add_user.html", name=name, role=role, users=user)



@app.route("/edit_user/<string:id>, <string:name>, <string:role>", methods=['POST', 'GET'])
def edit_user(id,name,role):
    #url = 'http://127.0.0.1:5000/edit_user/1?name=ingpedro1007@gmail.com&role=admin'
    #parsed_url = urlparse(url)
    #name = parse_qs(parsed_url.query)['name'][0]
    #role = parse_qs(parsed_url.query)['role'][0]
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()

    if request.method == 'POST':
        name = request.form['name']
        mobile = request.form['mobile']
        email = request.form['email']
        #imagelink = request.form['imagelink']

        destination_path = ""
        fileobj = request.files['file']
        file_extensions = ["JPG", "JPEG", "PNG", "GIF"]
        uploaded_file_extension = fileobj.filename.split(".")[1]
        # validating file extension
        if (uploaded_file_extension.upper() in file_extensions):
            destination_path = f"static/uploads/{fileobj.filename}"
            fileobj.save(destination_path)

            con = sql.connect("instance/flask_auth4.db")
            cur = con.cursor()
            cur.execute("update user set name=?,mobile=?,email=?,imagelink=? where id=?",
                        (name, mobile, email, destination_path, id))
            con.commit()
            flash('User Updated', 'success')
            return redirect(url_for("users"))
        else:
            flash('only images are accepted', 'danger')
            return redirect(url_for("users"))


    con = sql.connect("instance/flask_auth4.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from user where id=?", (id,))
    data = cur.fetchone()
    return render_template("edit_user.html", name=name, role=role, users=user, datas=data)


@app.route("/delete_user/<string:id>", methods=['GET'])
def delete_user(id):
    con = sql.connect("instance/flask_auth4.db")
    cur = con.cursor()
    cur.execute("delete from user where id=?", (id,))
    con.commit()
    flash('User Deleted', 'warning')
    return redirect(url_for("users"))


@app.route("/delete_user_role/<string:id>", methods=['GET'])
def delete_user_role(id):
    con = sql.connect("instance/flask_auth4.db")
    cur = con.cursor()
    cur.execute("delete from roleuser where id=?", (id,))
    con.commit()
    flash('User Role Deleted', 'warning')
    return redirect(url_for("role_users"))

@app.route("/show_user_role/<string:name>, <string:role>", methods=['POST', 'GET'])
def show_user_role(name,role):
    #url = 'http://127.0.0.1:5000/edit_user/1?name=ingpedro1007@gmail.com&role=admin'
    #parsed_url = urlparse(url)
    #name = parse_qs(parsed_url.query)['name'][0]
    #role = parse_qs(parsed_url.query)['role'][0]
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()
    id = user.id

    return render_template("show_user_role.html", name=name, role=role, logged_in=True, users=user, id=id)

@app.route("/edit_user_role/<string:name>, <string:role>", methods=['POST', 'GET'])
def edit_user_role(name,role):
    #url = 'http://127.0.0.1:5000/edit_user/1?name=ingpedro1007@gmail.com&role=admin'
    #parsed_url = urlparse(url)
    #name = parse_qs(parsed_url.query)['name'][0]
    #role = parse_qs(parsed_url.query)['role'][0]
    result = db.session.execute(db.select(Roleuser).where(Roleuser.email == current_user.email))
    user = result.scalar()
    id = user.id

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )

        # imagelink = request.form['imagelink']

        destination_path = ""
        fileobj = request.files['file']
        file_extensions = ["JPG", "JPEG", "PNG", "GIF"]
        uploaded_file_extension = fileobj.filename.split(".")[1]
        # validating file extension
        if (uploaded_file_extension.upper() in file_extensions):
            destination_path = f"static/uploads_roles/{fileobj.filename}"
            fileobj.save(destination_path)

            con = sql.connect("instance/flask_auth4.db")
            cur = con.cursor()
            cur.execute("update roleuser set name=?,email=?,password=?,imagelink=? where id=?",
                        (name, email, hash_and_salted_password, destination_path , id))
            con.commit()
            logout()
            flash('User Updated', 'success')
            return redirect(url_for("home"))
        else:
            flash('only images are accepted', 'danger')
            return redirect(url_for("users"))

    con = sql.connect("instance/flask_auth4.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from user where id=?", (id,))
    data = cur.fetchone()

    return render_template("edit_user_role.html", name=name, role=role, logged_in=True, users=user, datas=data, id=id)

if __name__ == "__main__":
    app.run(debug=False)
