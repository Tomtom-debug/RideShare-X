# Rideshare-X App
Rideshare-X is an app tailored specifically for Cornell University students. It aims to facilitate safe, convenient, and cost-effective transportation options for students traveling between campus and various destinations. Users can sign up using their Cornell email addresses to ensure the integrity of the community. The app will allow drivers to post rides they're offering, while passengers can search for available rides based on their destination and departure preferences. The repository for the RideshareX app's backend code has been skillfully developed by Samuel Tawiah, Kellan Liu, Su Huang and the frontend code has also been skillfully developed by Kayton Buerlein!. Additionally, the deployment and network traffic control were all handled by Samuel Tawiah.

## API SPECIFICATION ##
This document outlines the API endpoints and functionalities for the RideshareX app backend.
### Authenticate Username ###
- **Method:** POST
- **Endpoint:** */rideshare/authenticate/*
- **Description:** Authenticate a user by providing username and password.
- **Success Response (200):** Returns user details upon successful authentication.

### Get All Rides ###
- **Method:** GET
- **Endpoint:** */rideshare/rides/*
- **Description:** Retrieve information about all available rides.
- **Success Response (200):** Returns a list of all available rides.

### Get Specific Ride ###
- **Method:** GET
- **Endpoint:** */rideshare/rides/int:ride_id/*
- **Description:** Retrieve details of a specific ride.
- **Success Response (200):** Returns details of the specific ride.

### Post a Ride ###
- **Method:** POST
- **Endpoint:** */rideshare/addtrip/int:ride_id/*
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

### Get Rides for a Specific Driver ###
- **Method:** GET
- **Endpoint:** */rideshare/int:driver_id/*
- **Description:** Retrieve rides for a specific driver.
- **Success Response (200):** Returns a list of rides associated with the driver.
