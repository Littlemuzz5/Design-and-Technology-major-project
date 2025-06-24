from flask import Flask, render_template, request, jsonify, send_from_directory, render_template_string, Response, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
import os
from werkzeug.utils import secure_filename
from flask_migrate import Migrate



app = Flask(__name__)

app.secret_key = os.urandom(24)




# -----------------------------
# Database Setup
# -----------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://muzzboost_db_user:CCHQQ8Hk6JBONu3hp1kwgM6a8SlT7Ufl@dpg-d0j2k32dbo4c73bvb5cg-a/muzzboost_db?sslmode=require"
db = SQLAlchemy(app)




login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Task model (for the to-do feature)
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {"id": self.id, "text": self.text}

# Order model (for form submission)
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)

# User model (for signups)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)

class AccountListing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.String(20), nullable=False)
    image_url = db.Column(db.String(255))  # store 'img123.jpg'
    approved = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    owner = db.relationship('User', backref='listings')






# Create tables
with app.app_context():
    db.drop_all()
    db.create_all()




    app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='yourgmail@gmail.com',
    MAIL_PASSWORD='ioqj xicg fzdl rsch',  # App password recommended
    MAIL_DEFAULT_SENDER='yourgmail@gmail.com'
)

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# -----------------------------
# Page Routes
# -----------------------------

@app.route("/")
def home():
    return render_template("main.html")

@app.route("/accounts")
def accounts():
    return render_template("Accounts.html")

@app.route("/bot-lobbies")
def bot_lobbies():
    return render_template("bot lobbies.html")

@app.route("/hard-unlock")
def hard_unlock():
    return render_template("hard unlock.html")

@app.route("/nukes")
def nukes():
    return render_template("nukes.html")

@app.route("/old-bundles")
def old_bundles():
    return render_template("old bundles.html")

@app.route("/unreleased-bundles")
def unreleased_bundles():
    return render_template("Unrealsed bundles.html")

@app.route("/socials")
def socials():
    return render_template("Socials.html")

@app.route("/moving-code")
def moving_code():
    return render_template("moving code.html")

@app.route("/please-confirm")
def please_confirm():
    return "Please check your email to confirm your account."

@app.route("/admin")
@login_required
def admin_panel():
    if current_user.email != "ethanplm091@gmail.com":
        return "Access denied", 403

    orders = Order.query.all()
    listings = AccountListing.query.all()
    return render_template("admin.html", orders=orders, listings=listings)

@app.route("/approve-order/<int:order_id>", methods=["POST"])
@login_required
def approve_order(order_id): 
    if current_user.email != "ethanplm091@gmail.com":
        return "Access denied", 403
    order = Order.query.get_or_404(order_id)
    # You can add logic here like setting order.approved = True
    db.session.delete(order)  # or mark as processed
    db.session.commit()
    return redirect("/admin")

@app.route("/reject-order/<int:order_id>", methods=["POST"])
@login_required
def reject_order(order_id):
    if current_user.email != "ethanplm091@gmail.com":
        return "Access denied", 403
    order = Order.query.get_or_404(order_id)
    db.session.delete(order)
    db.session.commit()
    return redirect("/admin")


@login_required
def approve_listing(listing_id):
    if current_user.email != "ethanplm091@gmail.com":
        return "Access denied", 403
    listing = AccountListing.query.get_or_404(listing_id)
    listing.approved = True
    db.session.commit()
    return redirect("/admin")

@app.route("/reject-listing/<int:listing_id>", methods=["POST"])
@login_required
def reject_listing(listing_id):
    if current_user.email != "ethanplm091@gmail.com":
        return "Access denied", 403
    listing = AccountListing.query.get_or_404(listing_id)
    db.session.delete(listing)
    db.session.commit()
    return redirect("/admin")


@app.route("/please-confirm")
def please_confirm():
    return render_template_string("""
    <h2>Please Confirm Your Email</h2>
    <p>We've sent a confirmation link to your email. Click it to activate your account.</p>
    <p>If you didn’t receive the email, you can request a new one below:</p>
    
    <form method="POST" action="/resend-confirmation">
        <input type="email" name="email" placeholder="Enter your email again" required>
        <button type="submit">Resend Confirmation Email</button>
    </form>
    """)



@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        email = s.loads(token, salt="email-confirm", max_age=3600)
    except:
        return "Link expired or invalid"

    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        return "Already confirmed."
    
    user.confirmed = True
    db.session.commit()
    return "Email confirmed!"





def email_confirmed_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.confirmed:
            return redirect('/please-confirm')
        return f(*args, **kwargs)
    return decorated_function


@app.route("/resend-confirmation", methods=["GET", "POST"])
def resend_confirmation():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()

        if not user:
            return "Email not found.", 404
        if user.confirmed:
            return "Account already confirmed."

        # Resend the confirmation link
        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        msg = Message('Resend Confirmation - MuzzBoost', recipients=[email])
        msg.body = f'Click here to confirm your account: {link}'
        mail.send(msg)

        return f"Confirmation email resent to {email}."

    return render_template_string("""
        <h2>Resend Confirmation Email</h2>
        <form method="POST">
            <label>Email:</label>
            <input type="email" name="email" required>
            <button type="submit">Resend</button>
        </form>
    """)



@app.route("/admin/listings")
@login_required
def admin_listings():
    if current_user.email != "ethanplm091@gmail.com":
        abort(403)

    listings = AccountListing.query.filter_by(status="pending").all()
    return render_template_string("""
    <h1>Pending Customer Listings</h1>
    {% for item in listings %}
      <div style="border:1px solid #ccc; padding: 1rem; margin-bottom: 1rem;">
        <h2>{{ item.title }}</h2>
        <p>{{ item.description }}</p>
        <p><strong>Price:</strong> {{ item.price }}</p>
        {% if item.image_url %}
          <img src="{{ url_for('static', filename='uploads/' + item.image_url) }}" width="300">
        {% endif %}
        <form action="/approve/{{ item.id }}" method="POST" style="display:inline;">
          <button>Approve</button>
        </form>
        <form action="/reject/{{ item.id }}" method="POST" style="display:inline;">
          <button>Reject</button>
        </form>
      </div>
    {% endfor %}
    """, listings=listings)

@app.route("/approve/<int:item_id>", methods=["POST"])
@login_required
def approve_listing(item_id):
    if current_user.email != "ethanplm091@gmail.com":
        abort(403)

    listing = AccountListing.query.get_or_404(item_id)
    listing.status = "approved"
    db.session.commit()
    return redirect("/admin/listings")




@app.route("/customer-products")
def customer_products():
    listings = AccountListing.query.filter_by(approved=True).all()
    return render_template("customer products.html", listings=listings)



@app.route("/payment", methods=["GET", "POST"])
def payment():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        account_number = request.form.get("accountName")

        if not username or not email or not account_number:
            return "Missing data", 400

        new_order = Order(username=username, email=email, account_number=account_number)
        db.session.add(new_order)
        db.session.commit()
        return redirect("/user")

    
    



# -----------------------------
# Tasks API
# -----------------------------

@app.route("/api/tasks", methods=["GET"])
def get_tasks():
    tasks = Task.query.all()
    return jsonify([task.to_dict() for task in tasks]), 200

@app.route("/api/tasks", methods=["POST"])
def create_task():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "Invalid data"}), 400

    new_task = Task(text=data["text"])
    db.session.add(new_task)
    db.session.commit()
    return jsonify(new_task.to_dict()), 201

@app.route("/api/tasks/<int:task_id>", methods=["DELETE"])
def delete_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    db.session.delete(task)
    db.session.commit()
    return jsonify({"message": f"Task {task_id} deleted"}), 200

# -----------------------------
# Signup
# -----------------------------
@app.route("/signup", methods=["POST"])
def signup():
    email = request.form.get("email")
    password = request.form.get("psw")
    repeat = request.form.get("psw-repeat")

    if not email or not password or password != repeat:
        return "Invalid input or passwords do not match", 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return "Email already registered", 400

    # Create user with confirmed=False
    new_user = User(email=email, password=generate_password_hash(password), confirmed=False)
    db.session.add(new_user)
    db.session.commit()

    # Send confirmation email
    token = s.dumps(email, salt='email-confirm')
    link = url_for('confirm_email', token=token, _external=True)
    msg = Message('Confirm your email', recipients=[email])
    msg.body = f'Click here to confirm: {link}'
    mail.send(msg)

    return redirect("/please-confirm")








UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/submit-listing", methods=["POST"])
@login_required
def submit_listing():
    try:
        title = request.form["title"]
        description = request.form["description"]
        price = request.form["price"]
        file = request.files["image"]

        if not file or file.filename == '':
            return "No image selected", 400
        if not allowed_file(file.filename):
            return "Invalid file type", 400

        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        listing = AccountListing(
            title=title,
            description=description,
            price=price,
            image_url=filename,  # just the filename now
            status="pending",
            owner_id=current_user.id
        )

        db.session.add(listing)
        db.session.commit()
        return redirect("/user")
    except Exception as e:
        return f"Error submitting listing: {e}", 500


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return "<h2>You have been logged out.</h2><a href='/'>Go to Home</a>"


# -----------------------------
# Login
# -----------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # 🐛 Debug logs
        print(f"Login attempt: {email} / {password}")

        user = User.query.filter_by(email=email).first()
        print(f"Found user: {user}")
        print(f"Password match: {check_password_hash(user.password, password) if user else 'n/a'}")

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(request.args.get('next') or '/user')
        else:
            return "Invalid email or password", 401

    return render_template('login.html')


@app.route("/user")
@login_required
def user_dashboard():
    user_orders = Order.query.filter_by(email=current_user.email).all()
    return render_template("user.html", user=current_user, orders=user_orders)






# -----------------------------
# Admin Page
# -----------------------------

def check_auth(username, password):
    return username == "admin" and password == "Littlemuzz30"

def authenticate():
    return Response(
        "Access denied.\n", 401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )

@app.route("/admin-orders")
def view_orders():
    auth = request.authorization
    if not auth or not (auth.username == "ethan" and auth.password == "admin"):
        return "Access denied", 403
    orders = Order.query.all()
    return render_template_string("""
        <h2>Submitted Orders</h2>
        <table border="1" cellpadding="6">
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Account #</th>
                <th>Action</th>
            </tr>
            {% for o in orders %}
            <tr>
                <td>{{ o.id }}</td>
                <td>{{ o.username }}</td>
                <td>{{ o.email }}</td>
                <td>{{ o.account_number }}</td>
                <td>
                    <form action="/delete/{{ o.id }}" method="POST" onsubmit="return confirm('Delete this order?');">
                        <button type="submit">Delete</button>
                    </form>
                </td>
            </tr>
            {% endfor %}
        </table>
    """, orders=orders)

@app.route("/delete/<int:order_id>", methods=["POST"])
def delete_order(order_id):
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return authenticate()

    order = Order.query.get_or_404(order_id)
    db.session.delete(order)
    db.session.commit()
    return redirect("/admin")

# -----------------------------
# Service Worker
# -----------------------------
@app.route("/service-worker.js")
def service_worker():
    return send_from_directory("static/js", "service-worker.js")





#------------------------------
# My own Page
#------------------------------

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.email != "ethanplm091@gmail.com":
            return "Access denied", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route("/editor", methods=["GET", "POST"])
@login_required
@admin_required
def editor():
    templates_dir = os.path.join(app.root_path, "templates")
    pages = [f for f in os.listdir(templates_dir) if f.endswith(".html")]

    if request.method == "POST":
        page = request.form.get("page")
        content = request.form.get("content")
        path = os.path.join(templates_dir, page)

        if os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            flash("Page updated successfully.")
        else:
            flash("File not found.")

    selected_page = request.args.get("page")
    file_content = ""
    if selected_page:
        path = os.path.join(templates_dir, selected_page)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                file_content = f.read()

    return render_template("editor.html", pages=pages, content=file_content, selected=selected_page)


# -----------------------------
# Run App
# -----------------------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)