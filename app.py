from flask import Flask, render_template, request, jsonify, send_from_directory, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask import Response
import os

app = Flask(__name__)

# -----------------------------
# Database Setup
# -----------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://muzzboost_db_user:CCHQQ8Hk6JBONu3hp1kwgM6a8SlT7Ufl@dpg-d0j2k32dbo4c73bvb5cg-a/muzzboost_db"
db = SQLAlchemy(app)

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
    account_number = db.Column(db.String(50), nullable=False)  # new field

# Create tables
with app.app_context():
    db.create_all()

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

        return f"<h2>Thanks {username}, your request for Account #{account_number} has been received!</h2><a href='/'>Back to Home</a>"

    return render_template("payment.html")


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
# Service Worker
# -----------------------------

@app.route("/service-worker.js")
def service_worker():
    return send_from_directory("static/js", "service-worker.js")

def check_auth(username, password):
    return username == "admin" and password == "Littlemuzz30"

def authenticate():
    return Response(
        "Access denied.\n", 401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )


@app.route("/admin")
def view_orders():
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return authenticate()

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
# Run App
# -----------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
