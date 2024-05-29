# Rideshare-X App
Rideshare-X is a specialized transportation app designed exclusively for Cornell University students. It provides a secure, convenient, and affordable way for students to travel between campus and various destinations. By requiring users to register with their Cornell email addresses, the app maintains a trusted and reliable community.

The app offers a range of features to enhance the user experience:

- Drivers can easily post rides they are offering.
- Passengers can search for available rides based on their preferred destination and departure time.
- User Authentication ensures only Cornell students can join, enhancing safety and trust.
- Session Management keeps user data secure with session tokens and refresh tokens.

## API SPECIFICATION ##
This document outlines the API endpoints and functionalities for the RideshareX app backend.
### Register Account ###
- **Method:** POST
- **Endpoint:** */rideshare/register/*
- **Description:** Authenticate a user by providing username which must be a Cornell University email and password.
- **Success Response (201):** Returns user session token details upon successful authentication and creation.

### Login Account ###
- **Method:** POST
- **Endpoint:** */rideshare/login/*
- **Description:**  Log in a user and renew the session
- **Success Response (200):** Returns user session token details upon successful login.

### Refresh Session ###
- **Method:** POST
- **Endpoint:** */rideshare/session/*
- **Description:**   Update a user's session
- **Success Response (200):** Returns user session token details upon successful refresh.

### Secret Message ###
- **Method:** GET
- **Endpoint:** */rideshare/secret/*
- **Description:**   Verify a session token and return a secret message.
- **Success Response (200):** Returns a secret message upon successful verification.

### Get All Rides ###
- **Method:** GET
- **Endpoint:** */rideshare/rides/*
- **Description:** Retrieve information about all available rides.
- **Success Response (200):** Returns a list of all available rides.

### Get All Users ###
- **Method:** GET
- **Endpoint:** */rideshare/users/*
- **Description:** Retrieve information about all existing Users.
- **Success Response (200):** Returns a list of all existing users.

### Get Specific Ride ###
- **Method:** GET
- **Endpoint:** */rideshare/rides/int:ride_id/*
- **Description:** Retrieve details of a specific ride.
- **Success Response (200):** Returns details of the specific ride.

### Post a Ride ###
- **Method:** POST
- **Endpoint:** */rideshare/addtrip/*
- **Description:**  Create a new ride.
- **Success Response (201):** Returns details of the newly created ride.

### Request a Ride ###
- **Method:** POST
- **Endpoint:** */rideshare/int:ride_id/requestride/*
- **Description:**  Request to join a ride.
- **Success Response (201):** Returns booking details upon successful request.

### Deleting a Ride ###
- **Method:** DELETE
- **Endpoint:** */rideshare/delete/int:ride_id/*
- **Description:** Delete a ride.
- **Success Response (200):** Returns details of the deleted ride.

### Search Rides for a Specific Driver ###
- **Method:** GET
- **Endpoint:** */rideshare/rides/search/*
- **Description:** Retrieve rides for a specific driver.
- **Success Response (200):** Returns a list of rides associated with the driver.

### Search for Available Rides by Destination ###
- **Method:** GET
- **Endpoint:** */rideshare/rides/search/*
- **Description:**  search for available rides based on preferred destination.
- **Success Response (200):** Returns a list of available rides based on preferred destination