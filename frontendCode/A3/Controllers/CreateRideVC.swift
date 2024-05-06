//
//  CreateRideVC.swift
//  A3
//
//  Created by L20-US-KBuerlein23-MBA on 4/28/24.
//

import Foundation
import UIKit

class CreateRideVC: UIViewController {
    
    // MARK: - Properties (view)
    
    private var collectionView: UICollectionView!
    
    // MARK: - Properties (data)
    private let refreshControl = UIRefreshControl()
    
    private var rides: [Ride] = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        title = "Create a ride"
        navigationController?.navigationBar.prefersLargeTitles = true
        view.backgroundColor = UIColor.hc.white
        
        setUpCollectionView()
        collectionView.refreshControl = refreshControl
    }
    
    private func setUpCollectionView() {
        let layout = UICollectionViewFlowLayout()
        layout.scrollDirection = .vertical
        layout.minimumLineSpacing = 16
        layout.minimumInteritemSpacing = 16
        
        collectionView = UICollectionView(frame: .zero, collectionViewLayout: layout )
        
        collectionView.register(CreateRideCollectionViewCell.self, forCellWithReuseIdentifier: CreateRideCollectionViewCell.reuse)
        
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
    
    
extension CreateRideVC: UICollectionViewDelegate {  }

// MARK: - UICollectionViewDataSource

extension CreateRideVC: UICollectionViewDataSource {
    func collectionView(_ collectionView: UICollectionView, cellForItemAt indexPath: IndexPath) -> UICollectionViewCell {
        guard let cell = collectionView.dequeueReusableCell(withReuseIdentifier: CreateRideCollectionViewCell.reuse, for: indexPath) as? CreateRideCollectionViewCell else { return UICollectionViewCell() }
        return cell
    }
    
    func collectionView(_ collectionView: UICollectionView, numberOfItemsInSection section: Int) -> Int {
        return 1
    }
}
extension CreateRideVC: UICollectionViewDelegateFlowLayout {
    
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, sizeForItemAt indexPath: IndexPath) -> CGSize {
        return CGSize(width: 350, height: 250)
        
    }
}
