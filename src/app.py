from db import db, Users, Rides, Bookings
from flask import Flask, request
import json
from datetime import datetime
import os
# comment

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

# your routes here
@app.route("/rideshare/")
def hello_world():
    return ("Hello World")

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


@app.route("/rideshare/authenticate/", methods = ["POST"])
def create_user():
    """
    End point to create and authenticate email address of both old and new users
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
    
    #checking if a user already exist 
    user = Users.query.filter_by(username=username).first()
    if not user is None:
        return failure_response("User already exist",400)
    
    #creating a new user if it doesn't exist
    new_user = Users(username = username, password=password,
                    first_name=first_name,last_name=last_name)
    db.session.add(new_user)
    db.session.commit()
    return success_response(new_user.serialize(),201)
    

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
    return success_response({"users":[users.serialize() for users in Users.query.all()]})

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
@app.route("/rideshare/addtrip/<int:driver_id>/", methods = ["POST"])
def add_ride(driver_id):
    """
    add a trip
    """
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
    # getting request data
    body = json.loads(request.data)
    user_id = body.get("user_id")
    print("here")
    #check for missing fields 
    if None in (ride_id,user_id):
        return failure_response("Not found")
    # check if ride and user exist
    ride = Rides.query.filter_by(id=ride_id).first()
    print("here2")
    user = Users.query.filter_by(id=user_id).first()
    print("here3")
    if not ride or not user:
        return failure_response("Task not found")
    #check if there are available seats 
    if ride.available_seats == 0:
        return failure_response("No available seats")
    #create new booking if there are seats 
    time = datetime.now()
    new_booking = Bookings(ride_id=ride_id,passenger_id=user_id,booking_time=time)
    print("here4")
    ride.available_seats -= 1
    db.session.add(new_booking)
    db.session.commit()
    print("here5")
    return success_response(new_booking.serialize())

@app.route("/rideshare/<int:driver_id>/")
def request_ride_by_driver(driver_id):
    """
    Endpoint for getting all rides for a driver 
    """
    rides=[]
    rides_driver = Rides.query.filter_by(driver_id=driver_id).all()
    for ride in rides_driver:
        rides.append(ride.serialize())
    return success_response({"rides":rides})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
