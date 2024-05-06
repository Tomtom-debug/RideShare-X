
from flask_sqlalchemy import SQLAlchemy
from time import strftime

db = SQLAlchemy()

# your classes here

class Users(db.Model):
    """
    Course Model
    """
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    username = db.Column(db.String, nullable=False)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)

    # Relationship to Rides
    rides = db.relationship('Rides', backref='driver',  cascade="delete")
    # Relationship to Bookings
    bookings = db.relationship('Bookings', backref='passenger', cascade="delete")


    def __init__(self, **kwargs):
        """
        Initialize the user object
        """
        self.username = kwargs.get("username")
        self.first_name = kwargs.get("first_name")
        self.last_name = kwargs.get("last_name")
        self.password = kwargs.get("password")
    
    def serialize(self):

        return {
            "id": self.id,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,

        }

class Rides(db.Model):
    """
    For rides model
    """

    __tablename__ = "rides"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    driver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    origin = db.Column(db.String, nullable=False)
    destination = db.Column(db.String, nullable=False)
    departure_time = db.Column(db.String, nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)

    bookings = db.relationship('Bookings', backref='ride', cascade="delete")
    def __init__(self, **kwargs):
        """
        Initialize rides table
        """
        self.driver_id = kwargs.get("driver_id")
        self.origin = kwargs.get("origin")
        self.destination = kwargs.get("destination")
        self.departure_time = kwargs.get("departure_time")
        self.available_seats = kwargs.get("available_seats")

    def serialize(self):
        """
        Serialize the ride model
        """
        driver = Users.query.filter_by(id = self.driver_id).first()

        return{
            "ride_id": self.id,
            "driver_id": self.driver_id,
            "driver_first_name": driver.first_name,
            "driver_last_name": driver.last_name,
            "origin" : self.origin,
            "destination": self.destination,
            "departure_time": self.departure_time,
            "available_seats": self.available_seats
        }
    
class Bookings(db.Model):
    """
    For booking model
    """

    __tablename__ = "bookings"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ride_id = db.Column(db.Integer, db.ForeignKey("rides.id"), nullable=False)
    passenger_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    booking_time = db.Column(db.DateTime, nullable=False)


    def __init__(self, **kwargs):
        """
        Initialize the booking model
        """

        self.ride_id = kwargs.get("ride_id")
        self.passenger_id = kwargs.get("passenger_id")
        self.booking_time = kwargs.get("booking_time")

    def serialize(self):
        """
        Serialize the booking model
        """
        rides = Rides.query.filter_by(id=self.ride_id).first()
        return {
            "booking_id": self.id,
            "ride_id": self.ride_id,
            "passenger_id": self.passenger_id,
            "booking_time": self.booking_time.strftime('%Y/%m'),
            "origin" : rides.origin,
            "destination": rides.destination
        }
