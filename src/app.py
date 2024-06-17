import os
import json
import sqlite3
from datetime import datetime
from flask import Flask, request, redirect, url_for, session
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

# Local imports
from db import db, Users, Rides, Bookings, Asset
import users_dao

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
db_filename = "cms.db"

# Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# User session management setup
login_manager = LoginManager()
login_manager.init_app(app)

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)
with app.app_context():
    db.create_all()

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return Users.get(user_id)

# generalized response formats
def success_response(data, code=200):
    return json.dumps(data), code


def failure_response(message, code=404):
    return json.dumps({"error": message}), code


def extract_token(request):
    """
    Helper function that extracts the token from the header of a request
    """
    auth_header= request.headers.get("Authorization")
    if auth_header is None:
        return False, failure_response("Missing Authorization header")
    
    #Bearer <token>
    bearer_token = auth_header.replace("Bearer", "").strip()
    if bearer_token is None:
        return False, failure_response("Invalid Authorization header")
    
    return True, bearer_token
    
def check_token(request):
    """
    Helper function for verifying a session token
    """
    success,response = extract_token(request)
    if not success:
        return False,response 
    return True, response

def cache_token(request):
    """
    Helper function for getting an active user id 
    """
    success,response = check_token(request)
    if not success:
        return response
    session_token=response
    possible_user = users_dao.get_user_by_session_token(session_token)
    if not possible_user or not possible_user.verify_session_token(session_token):
        return False, failure_response("Invalid session token")
    return True, possible_user.id 

def get_google_provider_cfg():
    try:
        response = requests.get(GOOGLE_DISCOVERY_URL)
        response.raise_for_status()  # Raises an HTTPError if the status is 4xx, 5xx
        return response.json()
    except requests.exceptions.RequestException as e:
        return None 
    

#routes here
@app.route("/")
def hello_world():
    return ("Hello World")

@app.route("/rideshare/register/", methods = ["POST"])
def register_account():
    """
    Endpoint for registering a new user
    """
    body = json.loads(request.data)
    username = body.get("username")
    password = body.get("password")
    first_name = body.get("first_name")
    last_name = body.get("last_name")
    # Check if all required fields are present
    if None in (username, password, first_name, last_name):
        return failure_response("Missing a field",400)
    
    # authenticating username
    if not username.lower().endswith("@cornell.edu"):
        return failure_response("Invalid username",400)
    
    created,user = users_dao.create_user(first_name,last_name,username,password)
    if not created:
        return failure_response("User exist already")
    return success_response(user.serialize(),201)

@app.route("/rideshare/login/", methods=["POST"])
def login():
    """
    Endpoint for logging in a user
    """
    body = json.loads(request.data)
    username = body.get("username")
    password = body.get("password")
    # Check if all required fields are present
    if None in (username, password):
        return failure_response("Missing a field",400)
    
    success,user = users_dao.verify_credentials(username,password)
    if not success:
        return failure_response("Invalid credentials")
    user.renew_session()
    db.session.commit()
    return success_response(user.serialize())

@app.route("/rideshare/google/login/")
def google_login():
    # Finding out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    if google_provider_cfg is None:
        return failure_response("Failed to retrieve the Google provider configuration")
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens
    client.parse_request_body_response(json.dumps(token_response.json()))

    # with tokens let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        first_name = userinfo_response.json()["given_name"]
        last_name = userinfo_response.json().get("family_name")
    else:
        return failure_response("User email not available or not verified by Google.", 400)
    

    #login user if user already exist in the database 
    user= Users.query.filter(Users.username == users_email).first()
    if user:
        if picture != user.picture_url:
            user.picture_url = picture
            db.session.commit()
        user.renew_session()
        db.session.commit()
        return success_response(user.serialize())
    else:
         # authenticating username
        if not users_email.lower().endswith("@cornell.edu"):
            return failure_response("Invalid username",400)
        new_user = Users(username = users_email,picture=picture,
                    first_name=first_name,last_name=last_name)
        db.session.add(new_user)
        db.session.commit()
        return success_response(user.serialize(),201)

    
#use of Flask-Login to logout
#@app.route("/logout")
#@login_required
#def logout():
    #logout_user()
    #return redirect(url_for("hello_world"))


@app.route("/rideshare/session/", methods=["POST"])
def refresh_session():
    """
    Endpoint for updating a user's session
    """
    success,response = check_token(request)
    if not success:
        return response
    refresh_token = response

    try:
        user = users_dao.update_session(refresh_token)

    except Exception as e:
        return failure_response("Invalid refresh token")
    return success_response(user.serialize())


@app.route("/rideshare/secret/", methods=["GET"])
def secret_message():
    """
    Endpoint for verifying a session token and returning a secret message
    """
    success,response = cache_token(request)
    if not success:
        return response
    user_id = response
    possible_user = Users.query.filter_by(id = user_id).first()
    return success_response({"message":"Hello " + possible_user.first_name})


@app.route("/rideshare/logout/", methods=["POST"])
def logout():
    """
    Endpoint for logging out a user
    """
    success,response = cache_token(request)
    if not success:
        return response
    user_id = response
    possible_user = Users.query.filter_by(id = user_id).first()
    possible_user.session_expiration = datetime.now()
    db.session.commit()
    return success_response({"message":"You have been logged out"})


@app.route("/rideshare/delete/<int:ride_id>/", methods=["DELETE"])
def delete_a_ride(ride_id):
    """
    End point for delete a ride
    """

    ride = Rides.query.filter_by(id = ride_id).first()

    if ride is None:
        return failure_response("Ride not found")
    db.session.delete(ride)
    db.session.commit()
    return success_response(ride.serialize())

    

@app.route("/rideshare/rides/")
def get_all_rides():
    """
    End point for get all the rides
    """
    return success_response({"rides": [
        rides.serialize() for rides in Rides.query.all()
    ]})

@app.route("/rideshare/users/")
def get_all_users():
    '''
    End point for getting all the users
    '''
    return success_response({"users":[users.special_serialize() for users in Users.query.all()]})

@app.route("/rideshare/rides/<int:ride_id>/")
def get_specific_ride(ride_id):
    """
    End point for getting specific rides
    """

    ride = Rides.query.filter_by(id = ride_id).first()
    if ride is None:
        return failure_response("Ride not found")
    return success_response(ride.serialize())

#
@app.route("/rideshare/addtrip/", methods = ["POST"])
def add_ride():
    """
    add a trip
    """
    success,response = cache_token(request)
    if not success:
        return response
    driver_id = response
    body = json.loads(request.data)
    if "origin" not in body or "destination" not in body or "departure_time" not in body or "available_seats" not in body:
        return failure_response("Missing input", 400)
    origin = body.get("origin")
    destination = body.get("destination")
    departure_time = body.get("departure_time")
    available_seats = body.get("available_seats")

    if type(origin) is not str or type(destination) is not str or type(available_seats) is not int or type(departure_time) is not str :
        return failure_response("Incorrect input type", 400)
    
    try:
        date_time_obj = datetime.strptime(departure_time, '%m-%d-%y %H:%M')
    except ValueError:
        return failure_response("The date and time are not valid.", 400)
    
    new_ride = Rides(driver_id = driver_id, origin=origin, destination=destination, departure_time=departure_time, available_seats=available_seats)
    db.session.add(new_ride)
    db.session.commit()
    return success_response(new_ride.serialize(), 201)

@app.route("/rideshare/<int:ride_id>/requestride/", methods=["POST"])
def request_ride(ride_id):
    """
    Endpoint for requesting ride by id
    """
    success,response = cache_token(request)
    if not success:
        return response
    user_id = response
    # check if ride and user exist
    ride = Rides.query.filter_by(id=ride_id).first()
    user = Users.query.filter_by(id=user_id).first()
    if not ride or not user:
        return failure_response("Task not found")
    #check if there are available seats 
    if ride.available_seats == 0:
        return failure_response("No available seats")
    #create new booking if there are seats 
    time = datetime.now()
    try:
        departure_time = datetime.strptime(ride.departure_time, '%m-%d-%y %H:%M')
    except ValueError:
        return failure_response("Invalid departure time format in database")
    
    # Check if the ride is past its departure time
    if time > departure_time:
        return failure_response("Ride is unavailable due to past departure time")
    new_booking = Bookings(ride_id=ride_id,passenger_id=user_id,booking_time=time)
    ride.available_seats -= 1
    db.session.add(new_booking)
    db.session.commit()
    return success_response(new_booking.serialize())

@app.route("/rideshare/rides/driver/")
def all_rides_by_driver():
    """
    Endpoint for getting all rides for a driver 
    """
    success,response = cache_token(request)
    if not success:
        return response
    driver_id = response
    rides=[]
    rides_driver = Rides.query.filter_by(driver_id=driver_id).all()
    for ride in rides_driver:
        rides.append(ride.serialize())
    return success_response({"rides":rides})

@app.route("/rideshare/rides/search/", methods=["GET"])
def search_rides():
    body = json.loads(request.data)
    destination = body.get("destination")
    if destination is None:
        return failure_response("Missing a field")
    
    rides = Rides.query.filter(Rides.destination.ilike(f"%{destination}%")).all()
    
    if not rides:
        return failure_response("No rides found for the given destination")
    
    available_rides = []
    time = datetime.now()
    for ride in rides:
        try:
            departure_time = datetime.strptime(ride.departure_time, '%m-%d-%y %H:%M')
        except ValueError:
            return failure_response("Invalid departure time format in database")
        if departure_time > time:
            available_rides.append(ride.serialize())
    
    return success_response({"available rides":available_rides})

@app.route("/rideshare/upload/", methods=["POST"])
def upload():
    """
    Endpoint for uploading an image to AWS given its base64 form,
    then storing/returning the URL of that image
    """
    success,response = cache_token(request)
    if not success:
        return response
    user_id = response
    body = json.loads(request.data)
    image_data = body.get("image_data")
    if image_data is None:
        return failure_response("No Base64 URL")
    
    #create new Asset object 
    asset = Asset(image_data=image_data, user_id=user_id)
    db.session.add(asset)
    db.session.commit()
    return success_response(asset.serialize())
    

        

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
