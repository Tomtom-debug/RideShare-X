//
//  DeleteRideCollectionViewCell.swift
//  A3
//
//  Created by L20-US-KBuerlein23-MBA on 5/2/24.
//

import Foundation

import UIKit

class DeleteRideCollectionViewCell: UICollectionViewCell {
    
    //MARK: view properties
    private let originToDestination = UILabel()
    private let name = UILabel()
    private let time = UILabel()
    private let seats = UILabel()
    private let image = UIImageView()
    private let delete = UIButton()
    
    //MARK: data properties
    private let deleteText: String = "Delete ride"
    var ride_id = 0
    
    static let reuse = "DeleteRideCollectionViewCellReuse"
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        
        backgroundColor = UIColor.hc.white
        layer.cornerRadius = 16
        
        setUpImage()
        setUpOriginToDestination()
        setUpName()
        setUpTime()
        setUpAvailableSeats()
        setUpDeleteButton()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    //MARK - Set up views
    private func setUpImage() {
        image.image = UIImage(named: "car2")
        
        contentView.addSubview(image)
        image.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            //image.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            image.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
            image.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 50),
            image.widthAnchor.constraint(equalToConstant: 50),
            image.heightAnchor.constraint(equalToConstant: 50),
        ])
    }
    private func setUpName() {
        name.text = ""
        name.font = .systemFont(ofSize: 14, weight: .semibold)
        name.textColor = UIColor.hc.black
        
        contentView.addSubview(name)
        name.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            name.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 90),
            name.topAnchor.constraint(equalTo: originToDestination.bottomAnchor, constant: 20)
        ])
    }
    
    private func setUpOriginToDestination() {
        originToDestination.textColor = UIColor.hc.navyBlue
        originToDestination.font = .systemFont(ofSize: 20, weight: .semibold).rounded
        layer.cornerRadius = 16
        
        contentView.addSubview(originToDestination)
        originToDestination.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            originToDestination.centerXAnchor.constraint(equalTo: contentView.centerXAnchor),
            originToDestination.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 10)
        ])
    }
    
    private func setUpAvailableSeats() {
        seats.font = .systemFont(ofSize: 14, weight: .semibold)
        seats.textColor = UIColor.hc.black
        
        contentView.addSubview(seats)
        seats.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            seats.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 90),
            seats.topAnchor.constraint(equalTo: time.bottomAnchor, constant: 16),
        ])
    }
    
    private func setUpTime() {
        time.text = ""
        time.font = .systemFont(ofSize: 14, weight: .semibold)
        time.textColor = UIColor.hc.black
        
        contentView.addSubview(time)
        time.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            time.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 90),
            time.topAnchor.constraint(equalTo: name.bottomAnchor, constant: 16),
        ])
    }
    
    private func setUpDeleteButton() {
        delete.setTitle(deleteText, for: .normal)
        delete.setTitleColor(UIColor.hc.white, for: .normal)
        delete.backgroundColor = UIColor.hc.red
        delete.titleLabel?.font = UIFont.systemFont(ofSize: 12)
        delete.layer.cornerRadius = 6
        delete.addTarget(self, action: #selector(deleteRide), for: .touchUpInside)
        
        contentView.addSubview(delete)
        delete.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            delete.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -10),
            delete.topAnchor.constraint(equalTo: time.bottomAnchor, constant: 16),
            delete.widthAnchor.constraint(equalToConstant: 80),
            delete.heightAnchor.constraint(equalToConstant: 20),
            delete.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -10)
            
        ])
    }
    
    func configure(ride_id: Int, driver_id: Int, driver_first_name: String, driver_last_name: String, origin: String, destination: String, departure_time: String, available_seats: Int) {
        self.name.text = "Driver: \(driver_first_name) \(driver_last_name)"
        self.originToDestination.text = "\(origin) to \(destination)"
        self.time.text = "Departure time: \(departure_time)"
        self.seats.text = "Seats left: \(available_seats)"
        self.ride_id = ride_id
    }
    
    @objc private func deleteRide() {
        let ride_id = self.ride_id
        NetworkManager.shared.deleteRide(ride_id: ride_id) { ride in
        }
        
    }
    
    
}
