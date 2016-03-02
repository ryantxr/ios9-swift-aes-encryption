//
//  AESEncrypter.swift
//  AES Sample
//
//  Created by ryan teixeira on 3/1/16.
//  Copyright © 2016 Ryan Teixeira. All rights reserved.
//

import Foundation


//
//  Encrypter.swift
//  RealPayment
//
//  Created by ryan teixeira on 9/2/15.
//  Copyright (c) 2015 realmobiletech. All rights reserved.
//

import Foundation

public class AESEncrypter {
    
    var key:String
    var iv: String
    var errorMessage:String? // check this for errors(intended for debugging)
    
    init(key keyArg:String, iv ivArg:String) {
        key = keyArg
        iv = ivArg
    }
    
    /**
     * Encrypts data(String) using AES. This function expects the data to be correctly padded.
     * If it is not, the data will not be encrypted.
     */
    func encrypt(string: String) throws -> NSData {
        // Data
        let nsdata: NSData! = (string as NSString).dataUsingEncoding(NSUTF8StringEncoding) as NSData!
        return try encrypt(nsdata)
    }
    
    /**
     * Encrypts data(NSData) using AES. This function expects the data to be correctly padded.
     * If it is not, the data will not be encrypted.
     */
    func encrypt(data: NSData) throws -> NSData {
        // Data
        let dataLength    = Int(data.length)
        let dataBytes     = UnsafePointer<Void>(data.bytes)
        
        let cryptDataOpt    = NSMutableData(length: Int(dataLength) + kCCBlockSizeAES128)
        if cryptDataOpt == nil {
            throw NSError(domain: "Encrypter", code: 2, userInfo: ["message": "Failed to created cryptData"] )
        }
        let cryptData: NSMutableData = cryptDataOpt!
        let cryptPointer = UnsafeMutablePointer<Void>(cryptData.mutableBytes)
        let cryptLength  = Int(cryptData.length)
        
        // Key
        let keyData: NSData! = (key as NSString).dataUsingEncoding(NSUTF8StringEncoding) as NSData!
        print("keyData \(keyData)")
        let keyPtr: UnsafePointer<Void>!       = UnsafePointer<Void>(keyData.bytes)
        
        // first convert to NSData
        let ivData: NSData! = Hex.dataFromHexadecimalString(iv)
        let ivPtr = UnsafePointer<Void>(ivData.bytes) //as UnsafePointer<Void>!
        print("ivData \(ivData)")
        
        let keyLength              = Int(kCCKeySizeAES256)
        let operation: CCOperation = UInt32(kCCEncrypt)
        let algoritm:  CCAlgorithm = UInt32(kCCAlgorithmAES128)
        let options:   CCOptions   = CCOptions(0)
        //CCOptions(kCCOptionECBMode)
        
        var numBytesAffected :Int = 0
        
        let cryptStatus = CCCrypt(operation,
            algoritm,
            options,
            keyPtr, keyLength,
            ivPtr,
            dataBytes, dataLength,
            cryptPointer, cryptLength,
            &numBytesAffected)
        
        
        print("cryptStatus \(cryptStatus)")
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.length = numBytesAffected
            print("cryptLength = \(numBytesAffected), cryptData = \(cryptData)")
            let hexString = Hex.asHex(cryptData)
            print("crypto2 hex \(hexString)")
        }
        else {
            print("CCCrypt error")
            let userInfo : [NSObject: AnyObject] = ["message" : "failed to encrypt", ]
            throw NSError(domain: "Encrypter", code: 1, userInfo: userInfo)
        }
        
        /*
        CCCrypt(
        op: CCOperation,
        alg: CCAlgorithm,
        options: CCOptions,
        key: UnsafePointer<Void>,
        keyLength: Int,
        iv: UnsafePointer<Void>,
        dataIn: UnsafePointer<Void>,
        dataInLength: Int,
        dataOut: UnsafeMutablePointer<Void>,
        dataOutAvailable: Int,
        dataOutMoved: UnsafeMutablePointer<Int>)
        */
        return cryptData
    }
    
    /**
     * Encrypt data and add padding as necessary and output hex string.
     * The first byte of the input is the number of padding
     * that was added to the original data before being encrypted.
     * Encrypted data looks like this:
     *
     *  +- Number of padding bytes added
     *  |
     *  | +------------real data------------+ +-padding-+
     *  V |                                 | |         |
     * 04 61 62 63 64 61 62 63 64 61 62 63 64 00 00 00 00
     */
    func encryptPaddedToHex(data: NSData, error: NSErrorPointer) -> String {
        // Determine how much padding to add
        let padSize = (kCCBlockSizeAES128 - (data.length % kCCBlockSizeAES128)) % kCCBlockSizeAES128
        // add bytes to the end to pad to the needed block size
        let dataToEncrypt : NSMutableData = NSMutableData(data: data)
        if padSize > 0 {
            let spaces = String(count: padSize, repeatedValue: ("\0" as Character))
            dataToEncrypt.appendData(spaces.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!)
        }
        // encrypt
        var error1: NSError?
        var cryptData: NSData?
        do {
            cryptData = try encrypt(dataToEncrypt)
        } catch let error as NSError {
            error1 = error
            cryptData = nil
        }
        if let cryptData = cryptData {
            // prepend the padding size on the front
            let pre = String(format: "%02x", padSize)
            let hex = Hex.asHex(cryptData)
            return pre + hex
        }
        error.memory = error1
        return ""
    }
    
    func decrypt(data:NSData) throws -> NSData {
        let dataLength    = Int(data.length)
        let dataBytes     = UnsafePointer<Void>(data.bytes)
        
        let buf: Array<UInt8> = Array<UInt8>(count: dataLength, repeatedValue: 0)
        let cryptPointer = UnsafeMutablePointer<Void>(buf)
        let cryptLength = Int(dataLength) + kCCBlockSizeAES128
        
        // Key
        let keyData: NSData! = (key as NSString).dataUsingEncoding(NSUTF8StringEncoding) as NSData!
        print("keyData \(keyData)")
        let keyPtr: UnsafePointer<Void>!       = UnsafePointer<Void>(keyData.bytes)
        
        // first convert to NSData
        let ivData: NSData! = Hex.dataFromHexadecimalString(iv)
        let ivPtr = UnsafePointer<Void>(ivData.bytes) //as UnsafePointer<Void>!
        print("ivData \(ivData)")
        
        let keyLength              = Int(kCCKeySizeAES256)
        let operation: CCOperation = UInt32(kCCDecrypt)
        let algoritm:  CCAlgorithm = UInt32(kCCAlgorithmAES128)
        let options:   CCOptions   = CCOptions(0)
        var numBytesAffected :Int = 0
        
        let cryptStatus = CCCrypt(operation,
            algoritm,
            options,
            keyPtr, keyLength,
            ivPtr,
            dataBytes, dataLength,
            cryptPointer, cryptLength,
            &numBytesAffected)
        print("cryptStatus \(cryptStatus)")
        
        let cryptData = NSMutableData(bytes: buf, length: numBytesAffected)
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.length = numBytesAffected
            print("cryptLength = \(numBytesAffected), cryptData = \(cryptData)")
            let hexString = Hex.asHex(cryptData)
            print("crypto2 hex \(hexString)")
        }
        else {
            print("CCCrypt error")
            let userInfo : [NSObject: AnyObject] = ["message" : "failed to decrypt", ]
            throw NSError(domain: "Encrypter", code: 1, userInfo: userInfo)
        }
        return cryptData
    }
    
    /**
     * Decrypt data
     * The first byte of the input is the number of padding
     * that was added to the original data before being encrypted.
     * These have to be removed before decryption.
     */
    func decryptPaddedFromHex(hexString:String, error: NSErrorPointer) -> String {
        let possibleData = Hex.dataFromHexadecimalString(hexString)
        if let tmpData = possibleData {
            let range1 = NSRange(location: 0,length: 1)
            let sizeData = tmpData.subdataWithRange(range1)
            let range2 = NSRange(location: 1, length: tmpData.length-1)
            let encryptedData = tmpData.subdataWithRange(range2)
            
            print("sizeData \(sizeData)")
            print("data \(encryptedData)")
            var pad:Int = 0
            sizeData.getBytes(&pad, range: range1)
            print("decrypt pad \(pad)")
            
            var error: NSError? = nil
            var decryptedData: NSData?
            do {
                decryptedData = try decrypt(encryptedData)
            } catch let error1 as NSError {
                error = error1
                decryptedData = nil
            }
            _ = error
            if let decryptedData = decryptedData {
                let range3 = NSRange(location: 0, length: decryptedData.length - pad)
                let unpaddedData = decryptedData.subdataWithRange(range3)
                let result = NSString(data: unpaddedData, encoding:NSUTF8StringEncoding) as! String
                return result
            }
        }
        return ""
    }
}