from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash, check_password_hash
import pprint
import datetime
import jwt
from flask_cors import CORS
import mongo_functions

# flask pyjwt flask-cors

def token_required(f):
    def decorator(*args, **kwargs):
        token = None
        pprint.pprint(request.headers)
        if "X-Access-Token" in request.headers:
            token = request.headers["X-Access-Token"]

        if not token:
            return jsonify({"message": "A valid token is missing"})
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = USER_DATA.get(data.get("username"))
        except:
            return jsonify({"message": "Token is invalid"})

        return f(current_user, *args, **kwargs)
    return decorator


app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = "deadbeef"

USER_DATA = {
    "admin": {
        "email": "tom@king.pl",
        "password": "sha256$tWD5H6FrwFeqYyjk$4ee8fd5adf72b4bad365cbb5a41954ff1a8b8a3857d143c32389ca93e556800d",
        "username": "admin"
    }
}

@app.route("/", methods=["GET"])
def home():
    return jsonify(
            {
                "message":
                    "Congratulations, You have reached connectivity to the backend!"
            })


@app.route("/signup", methods=["POST"])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="sha256")

    USER_DATA[data["username"]] = {
        "email": data["email"],
        "username": data["username"],
        "password": hashed_password
    }
    pprint.pprint(USER_DATA)
    return jsonify({"message": "registered successfully"})


@app.route("/signin", methods=["POST"])
def login_user():
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return make_response("could not verify", 401, {"Authentication": "login required"})

    pprint.pprint(USER_DATA)
    user = USER_DATA.get(data.get("username"))
    pprint.pprint(user)

    if check_password_hash(user.get("password"), data.get("password")):
        token = jwt.encode({
            "username": user.get("username"),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60)},
            app.config["SECRET_KEY"])

        return jsonify({"token": token, "username": user.get("username"), "email": user.get("email"), "id": user.get("username"), "roles": []})

    return make_response("could not verify",  401, {"Authentication": "login required"})

@app.route("/user", methods=["GET"])
@token_required
def user_page(user):
    pprint.pprint(user)
    return jsonify({"message": f"You are correctly authenticated as `{user.get('username')}`"})

@app.route("/add_user")
def add_user():
    user_data = {
        "email": "tom@king.pl",
        "password": "sha256$tWD5H6FrwFeqYyjk$4ee8fd5adf72b4bad365cbb5a41954ff1a8b8a3857d143c32389ca93e556800d",
        "username": "admin"
    }

    saved_user = mongo_functions.insert_new_user(user_data)
    return jsonify(saved_user)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
