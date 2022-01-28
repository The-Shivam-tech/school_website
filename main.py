from flask import Flask, render_template, request, url_for, redirect
import requests
import random
import smtplib
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


app = Flask(__name__)
app.config["SECRET_KEY"]="its a secret key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_otp(to_addrs):
    otp = f"{random.randint(100000, 999999)}"
    connection = smtplib.SMTP("smtp.gmail.com", port=587)
    connection.starttls()
    connection.login(user="s92356674@gmail.com", password="9935679138Shivam")
    connection.sendmail(from_addr="s92356674@gmail.com", to_addrs=to_addrs,
                        msg=f"Subject:OTP for verification|| GonnaSchool\n\n {otp} is your otp of GonnaSchool account verification. \n It is valid for 5 minutes")
    connection.close()
    return otp


url = "https://api.countrystatecity.in/v1/countries/IN/states"

headers = {
    'X-CSCAPI-KEY': 'YmNXNmNoTGt4OThCdU5IRk84Y0lHRlphTUduUHlDQ1dBSDlKOFNzZQ=='
}

response = requests.request("GET", url, headers=headers)
states = response.json()

iso2_list = []
for state in states:
    iso2 = state["iso2"]
    iso2_list.append(iso2)
states_list = []
for state in states:
    state = state["name"]
    states_list.append(state)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    state = db.Column(db.String(), nullable=False)
    city = db.Column(db.String(), nullable=False)
    school = db.Column(db.String(), nullable=False)
    stu_class = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


# db.create_all()

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/courses")
def courses():
    return render_template("courses.html")


def cities_of_state(iso2):
    url_for_cities = f"https://api.countrystatecity.in/v1/countries/IN/states/{iso2}/cities"
    new_response = requests.request("GET", url_for_cities, headers=headers)
    cities = new_response.json()
    return cities


@app.route("/account", methods=["POST", "GET"])
def account():
    global iso2
    global email_otp
    global name
    global email
    global password
    global select
    global created_or_not
    created_or_not="no"
    global profile_letter
    profile_letter="no"
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        select = request.form["select"]
        index = states_list.index(select)
        iso2 = iso2_list[index]
        # email_otp=send_otp(email)
        email_otp = "111111"
        email_otp = f"{email_otp}a"
        print(name, email, password, select)
        return redirect(url_for("otp_page"))
    return render_template("create account.html", states=states, created=created_or_not, profile_letter=profile_letter)


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email=request.form["email"]
        password=request.form["password"]
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()

        # Check stored password hash against entered password hashed.
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/information", methods=["POST", "GET"])
def city():
    global city
    cities = cities_of_state(iso2=iso2)
    if request.method == "POST":
        city = request.form["select"]
        return redirect(url_for("school"))
    return render_template("city.html", cities=cities)


@app.route("/school", methods=["POST", "GET"])
def school():
    global created_or_not
    global profile_letter
    if request.method == "POST":
        school = request.form["school"]
        stu_class = request.form["class"]
        new_name = name
        new_email = email
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_state = state
        new_city = city
        print(new_name, new_city, new_state, school, stu_class)
        new_student = User(name=new_name, email=new_email, password=hash_and_salted_password, state=new_state, city=new_city,
                           school=school, stu_class=stu_class)
        db.session.add(new_student)
        db.session.commit()
        login_user(new_student)
        created_or_not="yes"
        profile_letter=new_name[0]
        return redirect(url_for("index"))
    return render_template("school.html")


# Verification and otp work

@app.route("/reset_password", methods=["POST", "GET"])
def email_for_otp():
    global email_otp
    if request.method == "POST":
        email = request.form["email"]
        # email_otp=send_otp(email)
        email_otp = "111111"
        email_otp = f"{email_otp}f"
        return redirect(url_for("otp_page"))
    return render_template("email_for_otp.html")


@app.route("/otp", methods=["POST", "GET"])
def otp_page():
    if request.method == "POST":
        otp = request.form["otp"]
        # print(otp)
        # print(email_otp)
        # print(email_otp[6])
        if email_otp[6] == "a":
            new_email_otp = email_otp.replace("a", "")
            # print(new_email_otp)
            if new_email_otp == otp:
                return redirect(url_for("city"))
            elif new_email_otp != otp:
                return redirect(url_for("otp_verify_page"))
        elif email_otp[6] == "f":
            new_email_otp = email_otp.replace("f", "")
            # print(new_email_otp)
            if new_email_otp == otp:
                return redirect(url_for("change"))
            elif new_email_otp != otp:
                return redirect(url_for("otp_verify_page"))
    return render_template("otp_page.html", verify_response="valid")


@app.route("/otp_verify")
def otp_verify_page():
    return render_template("otp_page.html", verify_response="Invalid otp")


@app.route("/reset password", methods=["POST", "GET"])
def change():
    if request.method == "POST":
        return redirect(url_for("change"))
    return render_template("change.html")

@app.route("/secret")
@login_required
def secret():
    return render_template("secret.html")
if __name__ == "__main__":
    app.run(debug=True)
