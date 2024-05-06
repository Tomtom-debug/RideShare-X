
//
//  CreateRideCollectionViewCell
//

import UIKit
import Alamofire


class CreateRideCollectionViewCell: UICollectionViewCell {

    // MARK: - Properties (view)

    private let postButton = UIButton()
    private let origin = UILabel()
    private let originTextField = UITextField()
    private let destination = UILabel()
    private let destinationTextField = UITextField()
    private let time = UILabel()
    private let timeTextField = UITextField()
    private let availableSeats = UILabel()
    private let availableSeatsTextField = UITextField()
    

    // MARK: - Properties (data)

    static let reuse: String = "CreateRideCollectionViewCellReuse"

    // MARK: - init

    override init(frame: CGRect) {
        super.init(frame: frame)

        backgroundColor = UIColor.hc.white
        layer.cornerRadius = 16

        setUpOrigin()
        setUpOriginTextField()
        setUpDestination()
        setUpDestinationTextField()
        setUpTime()
        setUpTimeTextField()
        setUpAvailableSeats()
        setUpAvailableSeatsTextField()
        setUpPostButton()
      }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: - Set Up Views

    private func setUpOrigin() {
        origin.text = "Origin:"
        origin.textColor = UIColor.hc.black
        origin.font = .systemFont(ofSize: 16, weight: .semibold).rounded

        contentView.addSubview(origin)
        origin.translatesAutoresizingMaskIntoConstraints = false
        
        
        NSLayoutConstraint.activate([
            origin.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 10),
            origin.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 10)
        ])
    }
    
    private func setUpOriginTextField() {
        originTextField.placeholder = "Type here"
        originTextField.backgroundColor = UIColor.hc.silver
        originTextField.layer.cornerRadius = 4
        
        contentView.addSubview(originTextField)
        originTextField.translatesAutoresizingMaskIntoConstraints = false
        
        
        NSLayoutConstraint.activate([
            originTextField.leadingAnchor.constraint(equalTo: origin.trailingAnchor, constant: 10),
            originTextField.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 10)
        ])
        
    }
    
    private func setUpDestination() {
        destination.text = "Destination:"
        destination.textColor = UIColor.hc.black
        destination.font = .systemFont(ofSize: 16, weight: .semibold).rounded

        contentView.addSubview(destination)
        destination.translatesAutoresizingMaskIntoConstraints = false
        
        
        NSLayoutConstraint.activate([
            destination.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 10),
            destination.topAnchor.constraint(equalTo: origin.bottomAnchor, constant: 15)
        ])
    }
    
    private func setUpDestinationTextField() {
        destinationTextField.placeholder = "Type here"
        destinationTextField.backgroundColor = UIColor.hc.silver
        destinationTextField.layer.cornerRadius = 4
        
        contentView.addSubview(destinationTextField)
        destinationTextField.translatesAutoresizingMaskIntoConstraints = false
        
        
        NSLayoutConstraint.activate([
            destinationTextField.leadingAnchor.constraint(equalTo: destination.trailingAnchor, constant: 10),
            destinationTextField.topAnchor.constraint(equalTo: originTextField.bottomAnchor, constant: 15)
        ])
    }
    
    private func setUpTime() {
        time.text = "Date and time:"
        time.textColor = UIColor.hc.black
        time.font = .systemFont(ofSize: 16, weight: .semibold).rounded

        contentView.addSubview(time)
        time.translatesAutoresizingMaskIntoConstraints = false
        
        
        NSLayoutConstraint.activate([
            time.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 10),
            time.topAnchor.constraint(equalTo: destination.bottomAnchor, constant: 15)
        ])
    }
    
    private func setUpTimeTextField() {
        timeTextField.placeholder = "MM-DD-YY hour:min"
        timeTextField.backgroundColor = UIColor.hc.silver
        timeTextField.layer.cornerRadius = 4
        
        contentView.addSubview(timeTextField)
        timeTextField.translatesAutoresizingMaskIntoConstraints = false
        
        
        NSLayoutConstraint.activate([
            timeTextField.leadingAnchor.constraint(equalTo: time.trailingAnchor, constant: 10),
            timeTextField.topAnchor.constraint(equalTo: destinationTextField.bottomAnchor, constant: 15)
        ])
    }
    
    private func setUpAvailableSeats() {
        availableSeats.text = "Available seats:"
        availableSeats.textColor = UIColor.hc.black
        availableSeats.font = .systemFont(ofSize: 16, weight: .semibold).rounded

        contentView.addSubview(availableSeats)
        availableSeats.translatesAutoresizingMaskIntoConstraints = false
        
        
        NSLayoutConstraint.activate([
            availableSeats.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 10),
            availableSeats.topAnchor.constraint(equalTo: time.bottomAnchor, constant: 15)
        ])
    }
    
    private func setUpAvailableSeatsTextField() {
        availableSeatsTextField.placeholder = "Number of available seats"
        availableSeatsTextField.backgroundColor = UIColor.hc.silver
        availableSeatsTextField.layer.cornerRadius = 4
        
        contentView.addSubview(availableSeatsTextField)
        availableSeatsTextField.translatesAutoresizingMaskIntoConstraints = false
        
        
        NSLayoutConstraint.activate([
            availableSeatsTextField.leadingAnchor.constraint(equalTo: availableSeats.trailingAnchor, constant: 10),
            availableSeatsTextField.topAnchor.constraint(equalTo: timeTextField.bottomAnchor, constant: 15)
        ])
    }


    private func setUpPostButton() {
        postButton.backgroundColor = UIColor.hc.newBlue
        postButton.layer.cornerRadius = 4
        postButton.setTitle("Post Ride", for: .normal)
        postButton.setTitleColor(UIColor.hc.white, for: .normal)
        postButton.titleLabel?.font = .systemFont(ofSize: 14, weight: .semibold)
        postButton.addTarget(self, action: #selector(createPost), for: .touchUpInside)

        contentView.addSubview(postButton)
        postButton.translatesAutoresizingMaskIntoConstraints = false

        let sidePadding: CGFloat = 24
        NSLayoutConstraint.activate([
            postButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -sidePadding),
            postButton.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -sidePadding),
            postButton.widthAnchor.constraint(equalToConstant: 96),
            postButton.heightAnchor.constraint(equalToConstant: 32),
            //postButton.topAnchor.constraint(equalTo: textField.bottomAnchor, constant: 32)
        ])
    }

    // MARK: - Button Helpers

    @objc private func createPost() {
        let driver_id = UserDefaults.standard.integer(forKey: "driver_id")
        let origin = originTextField.text ?? ""
        let destination = destinationTextField.text ?? ""
        let time = timeTextField.text ?? ""
        let seats = availableSeatsTextField.text ?? ""
        let availSeats = Int(seats) ?? 0
        NetworkManager.shared.postNewRide(driver_id: driver_id, origin: origin, destination: destination, departure_time: time, available_seats: availSeats) { ride in
        }
        
    }
}
