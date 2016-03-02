//
//  ViewController.swift
//  AES Sample
//
//  Created by ryan teixeira on 3/1/16.
//  Copyright © 2016 Ryan Teixeira. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    
    @IBOutlet var inputTextField: UITextField!
    @IBOutlet var encryptedTextField: UITextField!
    @IBOutlet var decryptedTextField: UITextField!
    
    var AESKey = "sample34123412341234123412341234"
    var AESiv = "44454251445e37383132333434343839"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    @IBAction func doEncrypt(sender: AnyObject){
        encryptedTextField.text = inputTextField.text
        
        let encrypter = AESEncrypter(key: AESKey, iv: AESiv)
        
        let base64String = ((inputTextField.text! as NSString).dataUsingEncoding(NSUTF8StringEncoding))!.base64EncodedStringWithOptions(.Encoding64CharacterLineLength)
        let data = base64String.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)

        var err: NSError?
        let encryptedHex = encrypter.encryptPaddedToHex(data!, error: &err)
        encryptedTextField.text = encryptedHex
        
        // Call the JupiterAPI
        let decryptedStr = encrypter.decryptPaddedFromHex(encryptedHex, error: &err)

        let data1 = NSData(base64EncodedString: decryptedStr, options: NSDataBase64DecodingOptions(rawValue: 0))
        
        // Convert back to a string
        decryptedTextField.text = String(NSString(data: data1!, encoding: NSUTF8StringEncoding)!)
    }

}

