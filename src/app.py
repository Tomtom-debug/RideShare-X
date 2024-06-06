from db import db, Users, Rides, Bookings, Asset
from flask import Flask, request
import json
from datetime import datetime
import users_dao
import os


app = Flask(__name__)
db_filename = "cms.db"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)
with app.app_context():
    db.create_all()

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

@app.route("/upload/", methods=["POST"])
def upload():
    """
    Endpoint for uploading an image to AWS given its base64 form,
    then storing/returning the URL of that image
    """
    body = json.loads(request.data)
    image_data = body.get("image_data")
    if image_data is None:
        return failure_response("No Base64 URL")
    
    #create new Asset object 
    asset = Asset(image_data=image_data)
    db.session.add(asset)
    db.session.commit()
    return success_response(asset.serialize())
    

        

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
