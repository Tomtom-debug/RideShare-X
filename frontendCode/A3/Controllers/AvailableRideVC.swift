//
//  AvailableRideVC.swift
//  RideShare
//
//  Created by L20-US-KBuerlein23-MBA on 4/28/24.
//

import Foundation
import UIKit

class AvailableRideVC: UIViewController {
    
    // MARK: - Properties (view)
    
    private var collectionView: UICollectionView!
    
    // MARK: - Properties (data)
    private let refreshControl = UIRefreshControl()
    
    private var rides: [Ride] = []
        
        //Ride(ride_id: "ksajdfh", driver_id: "kljshadf", first_name: "Kayton", last_name: "Buerlein", origin: "Ithaca", destination: "Boston", departure_time: "5/8/2024, 8:00", available_seats: "3", bookings: "meow"),
        //Ride(ride_id: "ksajdfh", driver_id: "kljshadf", first_name: "Bowen", last_name: "Hall", origin: "Ithaca", destination: "NYC", departure_time: "5/17/2024, 8:00", available_seats: "5", bookings: "meow")
   // ]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        title = "Available Rides"
        navigationController?.navigationBar.prefersLargeTitles = true
        view.backgroundColor = UIColor.hc.offWhite
        
        setUpCollectionView()
        fetchAllRides()
        collectionView.refreshControl = refreshControl
    }
    
    @objc func fetchAllRides() {
        NetworkManager.shared.getAvailableRides { [weak self] rides in
            guard let self = self else {return}
            self.rides = rides.rides
            
            DispatchQueue.main.async {
                self.collectionView.reloadData()
                self.refreshControl.endRefreshing()
            }
        }
    }
    
    private func setUpCollectionView() {
        let layout = UICollectionViewFlowLayout()
        layout.scrollDirection = .vertical
        layout.minimumLineSpacing = 16
        layout.minimumInteritemSpacing = 16
        
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout )
        
        collectionView.register(RideCollectionViewCell.self, forCellWithReuseIdentifier: RideCollectionViewCell.reuse)
        
        collectionView.delegate = self
        collectionView.dataSource = self
        
        collectionView.backgroundColor = UIColor.hc.offWhite
        
        view.addSubview(collectionView)
        
        collectionView.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            collectionView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            collectionView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            collectionView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            collectionView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor)
        ])
        
    }

}

//MARK: UICollectionViewDelegate

extension AvailableRideVC: UICollectionViewDelegate {  }

// MARK: - UICollectionViewDataSource

extension AvailableRideVC: UICollectionViewDataSource {
    func collectionView(_ collectionView: UICollectionView, numberOfItemsInSection section: Int) -> Int {
        return rides.count
    }
    
    
    func collectionView(_ collectionView: UICollectionView, cellForItemAt indexPath: IndexPath) -> UICollectionViewCell {
        guard let cell = collectionView.dequeueReusableCell(withReuseIdentifier: RideCollectionViewCell.reuse, for: indexPath) as? RideCollectionViewCell else { return UICollectionViewCell() }
        let i = indexPath.row
        cell.configure(ride_id: rides[i].ride_id, driver_id: rides[i].driver_id, driver_first_name: rides[i].driver_first_name, driver_last_name: rides[i].driver_last_name, origin: rides[i].origin, destination: rides[i].destination, departure_time: rides[i].departure_time, available_seats: rides[i].available_seats)
        return cell
    }
}

extension AvailableRideVC: UICollectionViewDelegateFlowLayout {
    
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, sizeForItemAt indexPath: IndexPath) -> CGSize {
        return CGSize(width: 350, height: 150)
        
    }
}
