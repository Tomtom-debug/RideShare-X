"""
DAO (Data Access Object) file

Helper file containing functions for accessing data in our database
"""

from db import db,Users


def get_user_by_email(username):
    """
    Returns a user object from the database given an email
    """
    return Users.query.filter(Users.username == username).first()


def get_user_by_session_token(session_token):
    """
    Returns a user object from the database given a session token
    """
    return Users.query.filter(Users.session_token == session_token).first()


def get_user_by_refresh_token(refresh_token):
    """
    Returns a user object from the database given an update token
    """
    return Users.query.filter(Users.refresh_token == refresh_token).first()


def verify_credentials(username, password):
    """
    Returns true if the credentials match, otherwise returns false
    """
    possible_user = get_user_by_email(username)

    if possible_user is None:
        return False, None
    
    return possible_user.verify_password(possible_user),possible_user



def create_user(first_name,last_name,username, password):
    """
    Creates a User object in the database

    Returns if creation was successful, and the User object
    """
    #checking if a user already exist 
    possible_user = get_user_by_email(username)
    if possible_user is not None:
        return False, possible_user
    
    new_user = Users(username = username, password=password,
                    first_name=first_name,last_name=last_name)
    db.session.add(new_user)
    db.session.commit()
    return True, new_user
    


def update_session(refresh_token):
    """
    Renews a user's session token
    
    Returns the User object
    """
    possible_user = get_user_by_refresh_token(refresh_token)
    if possible_user is None:
        return Exception("Invalid refresh token")
    possible_user.renew_session()
    db.session.commit()
    return possible_user
