//
//  HomeScreenVC.swift
//  RideShare
//
//  Created by L20-US-KBuerlein23-MBA on 4/28/24.
//

import Foundation
import UIKit

class HomeScreenVC: UIViewController {
    
    //MARK: view properties
    private let available = UIButton()
    private let create = UIButton()
    private let text = UILabel()
    private let car1 = UIImageView()
    private let delete = UIButton()
    
    //MARK: data properties
    private let availableText = "Find a ride"
    private let createText = "Create a ride"
    private let deleteText = "Delete a ride"
    private let textText = "I want to..."
    
    //MARK: viewDidLoad
    override func viewDidLoad() {
        super.viewDidLoad()
        
        setUpCar1()
        setUpText()
        setUpAvailable()
        setUpCreate()
        setUpDelete()
        
        view.backgroundColor = UIColor.hc.white
    }
    
    private func setUpAvailable() {
        available.setTitle(availableText, for: .normal)
        available.setTitleColor(UIColor.hc.white, for: .normal)
        available.titleLabel?.font = UIFont.systemFont(ofSize: 24)
        available.backgroundColor = UIColor.hc.newBlue
        available.layer.cornerRadius = 16
        available.addTarget(self, action: #selector(pushAvailableRideVC), for: .touchUpInside)
        
        view.addSubview(available)
        available.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            available.topAnchor.constraint(equalTo: text.bottomAnchor, constant: 34),
            available.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 40),
            available.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -40),
            available.heightAnchor.constraint(equalToConstant: 100)
        ])
    }
    
    private func setUpText() {
        text.text = textText
        text.textColor = UIColor.hc.navyBlue
        text.font = .systemFont(ofSize: 30, weight: .semibold).rounded
        
        view.addSubview(text)
        text.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            text.topAnchor.constraint(equalTo: car1.bottomAnchor, constant: 10),
            text.centerXAnchor.constraint(equalTo: view.centerXAnchor)
        ])
    }
    
    private func setUpCar1() {
        car1.image = UIImage(named: "car1")
        
        view.addSubview(car1)
        car1.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            car1.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 50),
            car1.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            car1.widthAnchor.constraint(equalToConstant: 100),
            car1.heightAnchor.constraint(equalToConstant: 100)
        ])
    }
    
    private func setUpCreate() {
        create.setTitle(createText, for: .normal)
        create.setTitleColor(UIColor.hc.white, for: .normal)
        create.titleLabel?.font = UIFont.systemFont(ofSize: 24)
        create.backgroundColor = UIColor.hc.newBlue
        create.layer.cornerRadius = 16
        create.addTarget(self, action: #selector(pushCreateRideVC), for: .touchUpInside)
        
        view.addSubview(create)
        create.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            create.topAnchor.constraint(equalTo: available.bottomAnchor, constant: 34),
            create.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 40),
            create.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -40),
            create.heightAnchor.constraint(equalToConstant: 100)
        ])
    }
    private func setUpDelete() {
        delete.setTitle(deleteText, for: .normal)
        delete.setTitleColor(UIColor.hc.white, for: .normal)
        delete.titleLabel?.font = UIFont.systemFont(ofSize: 24)
        delete.backgroundColor = UIColor.hc.newBlue
        delete.layer.cornerRadius = 16
        delete.addTarget(self, action: #selector(pushDeleteRideVC), for: .touchUpInside)
        
        view.addSubview(delete)
        delete.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            delete.topAnchor.constraint(equalTo: create.bottomAnchor, constant: 34),
            delete.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 40),
            delete.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -40),
            delete.heightAnchor.constraint(equalToConstant: 100)
        ])
    }
    
    @objc private func pushAvailableRideVC() {
        let availableRideVC = AvailableRideVC()
        navigationController?.pushViewController(availableRideVC, animated: true)
        
    }
    
    @objc private func pushCreateRideVC() {
        let createRideVC = CreateRideVC()
        navigationController?.pushViewController(createRideVC, animated: true)
        
    }
    
    @objc private func pushDeleteRideVC() {
        let deleteRideVC = DeleteRideVC()
        navigationController?.pushViewController(deleteRideVC, animated: true)
        
    }
    
    
}
