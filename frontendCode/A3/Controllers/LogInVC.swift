//
//  LogInVC.swift
//  RideShare
//
//  Created by L20-US-KBuerlein23-MBA on 4/25/24.
//

import Foundation
import UIKit

class LogInVC: UIViewController {
    
    //MARK: view properties
    private let username = UITextField()
    private let user = UILabel()
    private let logIn = UIButton()
    private let password = UILabel()
    private let passwordText = UITextField()
    private let first_name = UITextField()
    private let last_name = UITextField()
    private let first_nameText = UILabel()
    private let last_nameText = UILabel()
    
    
    
    //MARK: data properties
    private let userText: String = "Enter Cornell email address:"
    private let userPlace: String = "Type email address here"
    private let logText: String = "Log In"
    private let passText: String = "Enter password:"
    private let passwordPlace: String = "Type password here"
    private let firstText: String = "First name"
    private let lastText: String = "Last name"
    private let nameText: String = "Type here"
    
    //MARK: viewDidLoad
    override func viewDidLoad() {
        super.viewDidLoad()
        
        title = "Log In"
        view.backgroundColor = UIColor.hc.white
        
        setUpUser()
        setUpUsername()
        setUpPassword()
        setUpPasswordText()
        setUpFirstName()
        setUpFirstNameText()
        setUpLastName()
        setUpLastNameText()
        setUpLogIn()

        
        let tap = UITapGestureRecognizer(target: self, action: #selector(UIInputViewController.dismissKeyboard))
        view.addGestureRecognizer(tap)
    
    }
    
    
    private func setUpUser() {
        user.text = userText
        user.textColor = UIColor.hc.black
        user.font = .systemFont(ofSize: 24, weight: .semibold).rounded
        
        view.addSubview(user)
        user.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            user.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            user.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 60),
    
        ])
    
        
    }
    
    private func setUpUsername() {
        username.placeholder = userPlace
        username.backgroundColor = UIColor.hc.silver
        username.layer.cornerRadius = 16
        
        view.addSubview(username)
        username.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            username.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            username.topAnchor.constraint(equalTo: user.bottomAnchor, constant: 20),
            username.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 40),
            username.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -40),
            username.heightAnchor.constraint(equalToConstant: 75),
            
        ])
    
    }
    
    
    private func setUpLogIn() {
        logIn.setTitle(logText, for: .normal)
        logIn.setTitleColor(UIColor.hc.white, for: .normal)
        logIn.backgroundColor = UIColor.hc.navyBlue
        logIn.titleLabel?.font = UIFont.systemFont(ofSize: 22)
        logIn.layer.cornerRadius = 16
        logIn.addTarget(self, action: #selector(pushHomeScreen), for: .touchUpInside)
        
        view.addSubview(logIn)
        logIn.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            logIn.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            logIn.topAnchor.constraint(equalTo: first_name.bottomAnchor, constant: 32),
            logIn.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 70),
            logIn.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -70),
            logIn.heightAnchor.constraint(equalToConstant: 75),
        ])
    }
    
    private func setUpPassword() {
        password.text = passText
        password.textColor = UIColor.hc.black
        password.font = .systemFont(ofSize: 24, weight: .semibold).rounded
        
        view.addSubview(password)
        password.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            password.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            password.topAnchor.constraint(equalTo: username.bottomAnchor, constant: 32),
            
        ])
    }
    private func setUpPasswordText() {
        passwordText.placeholder = passwordPlace
        passwordText.backgroundColor = UIColor.hc.silver
        passwordText.layer.cornerRadius = 16
        
        view.addSubview(passwordText)
        passwordText.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            passwordText.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            passwordText.topAnchor.constraint(equalTo: password.bottomAnchor, constant: 20),
            passwordText.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 40),
            passwordText.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -40),
            passwordText.heightAnchor.constraint(equalToConstant: 75),
            
        ])
    }
    
    private func setUpFirstName() {
        first_nameText.text = firstText
        first_nameText.textColor = UIColor.hc.black
        first_nameText.font = .systemFont(ofSize: 24, weight: .semibold).rounded
        
        view.addSubview(first_nameText)
        first_nameText.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            first_nameText.topAnchor.constraint(equalTo: passwordText.bottomAnchor, constant: 20),
            first_nameText.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 35),
            first_name.widthAnchor.constraint(equalToConstant: 150)
        ])
    }
    
    private func setUpFirstNameText() {
        first_name.placeholder = nameText
        first_name.backgroundColor = UIColor.hc.silver
        first_name.layer.cornerRadius = 16
        
        view.addSubview(first_name)
        first_name.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            first_name.topAnchor.constraint(equalTo: first_nameText.bottomAnchor, constant: 16),
            first_name.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 35),
            first_name.heightAnchor.constraint(equalToConstant: 75),
            first_name.widthAnchor.constraint(equalToConstant: 150)
            
        ])
    }
    
    private func setUpLastName() {
        last_nameText.text = lastText
        last_nameText.textColor = UIColor.hc.black
        last_nameText.font = .systemFont(ofSize: 24, weight: .semibold).rounded
        
        view.addSubview(last_nameText)
        last_nameText.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            last_nameText.topAnchor.constraint(equalTo: passwordText.bottomAnchor, constant: 20),
            last_nameText.leadingAnchor.constraint(equalTo: first_nameText.trailingAnchor, constant: 60),
            
        ])
    }
    
    private func setUpLastNameText() {
        last_name.placeholder = nameText
        last_name.backgroundColor = UIColor.hc.silver
        last_name.layer.cornerRadius = 16
        
        view.addSubview(last_name)
        last_name.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            last_name.topAnchor.constraint(equalTo: last_nameText.bottomAnchor, constant: 16),
            last_name.leadingAnchor.constraint(equalTo: first_name.trailingAnchor, constant: 20),
            last_name.heightAnchor.constraint(equalToConstant: 75),
            last_name.widthAnchor.constraint(equalToConstant: 150)
            
        ])
    }
    
    
    @objc private func pushHomeScreen() {
        let username = username.text ?? ""
        let password = passwordText.text ?? ""
        let first_name = first_name.text ?? ""
        let last_name = last_name.text ?? ""
        NetworkManager.shared.postAuthentication(username: username, password: password, first_name: first_name, last_name: last_name) { user in
            UserDefaults.standard.setValue(user.id, forKey: "driver_id")
        }
        let homeScreenVC = HomeScreenVC()
        navigationController?.pushViewController(homeScreenVC, animated: true)
        
    
}
    @objc func dismissKeyboard() {
        view.endEditing(true)
    }
}



