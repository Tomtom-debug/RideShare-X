//
//  NetworkManager.swift
//  RideShare
//
//  Created by L20-US-KBuerlein23-MBA on 4/28/24.
//

import Alamofire
import Foundation

class NetworkManager {
    
    /// Shared singleton instance
    static let shared = NetworkManager()
    
    let decoder: JSONDecoder = JSONDecoder()
    
    private init() { }
    
    /// Endpoint for dev server
    private let endpoint: String = "http://127.0.0.1:8000/rideshare/"
    
    // MARK: - Requests
    func getAvailableRides(completion: @escaping (RideResponse) -> Void) {
        AF.request("\(endpoint)rides/", method: .get)
            .validate()
            .responseDecodable(of: RideResponse.self, decoder: decoder) { response in
                switch response.result {
                case .success(let rides):
                    completion(rides)
                case .failure(let error):
                    print("Error in NetworkManager.getAvailableRides: \(error.localizedDescription)")
                }
            }
    }
    
    
    func postAuthentication(username: String, password: String, first_name: String, last_name: String, completion: @escaping (User) -> Void) {
        let parameters: Parameters = [
            "username": username,
            "password": password,
            "first_name": first_name,
            "last_name": last_name
        ]
        AF.request("\(endpoint)authenticate/", method: .post, parameters: parameters, encoding: JSONEncoding.default)
            .validate()
            .responseDecodable(of: User.self, decoder: decoder) { response in
                switch response.result {
                case .success(let user):
                    completion(user)
                case .failure(let error) :
                    print("Error in NetworkManager.postAuthentication: \(error.localizedDescription)")
                }
            }
    }
    func deleteRide(ride_id: Int, completion: @escaping (Ride) -> Void) {
        AF.request("\(endpoint)delete/\(ride_id)/", method: .delete, encoding: JSONEncoding.default)
            .validate()
            .responseDecodable(of: Ride.self, decoder: decoder) { response in
                switch response.result {
                case .success(let ride):
                    completion(ride)
                case .failure(let error) :
                    print("Error in NetworkManager.deleteRide: \(error.localizedDescription)")
                }
            }
    }
    func getDriverRides(driver_id: Int, completion: @escaping (RideResponse) -> Void) {
        AF.request("\(endpoint)\(driver_id)/", method: .get, encoding: JSONEncoding.default)
            .validate()
            .responseDecodable(of: RideResponse.self, decoder: decoder) { response in
                switch response.result {
                case .success(let rides):
                    completion(rides)
                case .failure(let error):
                    print("Error in NetworkManager.getDriverRides: \(error.localizedDescription)")
                }
            }
    }
    func postRequestJoin(ride_id: Int, completion: @escaping (RideResponse) -> Void) {
        let parameters: Parameters = [
            "ride_id": ride_id
        ]
        AF.request("\(endpoint)\(ride_id)/requestride/", method: .post, parameters: parameters, encoding: JSONEncoding.default)
            .validate()
            .responseDecodable(of: RideResponse.self, decoder: decoder) { response in
                switch response.result {
                case .success(let ride):
                    completion(ride)
                case .failure(let error) :
                    print("Error in NetworkManager.postAuthentication: \(error.localizedDescription)")
                }
            }
    }
    func postNewRide(driver_id: Int, origin: String, destination: String, departure_time: String, available_seats: Int, completion: @escaping (Ride) -> Void) {
        let parameters: Parameters = [
            "origin": origin,
            "destination": destination,
            "departure_time": departure_time,
            "available_seats": available_seats
        ]
        AF.request("\(endpoint)addtrip/\(driver_id)/", method: .post, parameters: parameters, encoding: JSONEncoding.default)
            .validate()
            .responseDecodable(of: Ride.self, decoder: decoder) { response in
                switch response.result {
                case .success(let ride):
                    completion(ride)
                case .failure(let error) :
                    print("Error in NetworkManager.postNewRide: \(error.localizedDescription)")
                }
            }
    }
}
