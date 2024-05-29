import datetime
import hashlib
import os

from flask_sqlalchemy import SQLAlchemy
from time import strftime
import bcrypt 

db = SQLAlchemy()

# your classes here

class Users(db.Model):
    """
    User Model
    """
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)

    # User information
    username = db.Column(db.String, nullable=False, unique=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    password_digest = db.Column(db.String, nullable=False)


    # Session information
    session_token = db.Column(db.String, nullable=False, unique=True)
    session_expiration = db.Column(db.DateTime, nullable=False)
    refresh_token = db.Column(db.String, nullable=False, unique=True)

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
        self.password_digest = bcrypt.hashpw(kwargs.get("password").encode("utf8"), bcrypt.gensalt(rounds=13))
        self.renew_session()

    def _urlsafe_base_64(self):
        """
        Randomly generates hashed tokens (used for session/update tokens)
        """
        return hashlib.sha1(os.urandom(64)).hexdigest()

    def renew_session(self):
        """
        Renews the sessions, i.e.
        1. Creates a new session token
        2. Sets the expiration time of the session to be a day from now
        3. Creates a new update token
        """
        self.session_token = self._urlsafe_base_64()
        self.session_expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        self.refresh_token = self._urlsafe_base_64()

    def verify_password(self, password):
        """
        Verifies the password of a user
        """
        return bcrypt.checkpw(password.encode("utf8"), self.password_digest)
    
    def verify_session_token(self, session_token):
        """
        Verifies the session token of a user
        """
        return session_token == self.session_token and datetime.datetime.now() < self.session_expiration
    
    def verify_update_token(self, refresh_token):
        """
        Verifies the update token of a user
        """
        return refresh_token == self.refresh_token

    def serialize(self):
        return {
            "session_token":self.session_token,
            "session_expiration": str(self.session_expiration),
            "refresh_token": self.refresh_token
        }
    
    def special_serialize(self):
        return {
            "first_name":self.first_name,
            "last_name":self.last_name
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
