//
//  Hex.swift
//  AES Sample
//
//  Created by ryan teixeira on 3/1/16.
//  Copyright © 2016 Ryan Teixeira. All rights reserved.
//

import Foundation


class Hex {
    /**
     * converts array of bytes to hex string.
     */
    class func asHex(arr: Array<UInt8>) -> String {
        var hexString = ""
        for byte in arr {
            hexString += String(format:"%02x", byte)
        }
        return hexString
    }
    
    /**
     * Converts NSData to a hex string
     */
    class func asHex(data: NSData?) -> String {
        if let data = data {
            var resultAsHex: String = ""
            data.enumerateByteRangesUsingBlock({ (bytes, range, stop) -> Void in
                let chars = UnsafePointer<UInt8>(bytes)
                for i in 0...range.length-1 {
                    resultAsHex += String(format: "%02x", UInt8(chars[i]))
                }
            })
            return resultAsHex
            
            /*
            let len = adata.length
            //        let b = data.bytes as! UnsafePointer<UInt8>
            //let pbytes = UnsafePointer<UInt8>(data.bytes) as [UInt8]
            var bytes = [UInt8](count: adata.length, repeatedValue: 0)
            adata.getBytes(&bytes, length: adata.length)
            var hexString: String = ""
            //        for i in 0...len-1 {
            for byte in bytes {
            hexString += String(format:"%02x", byte)
            }
            
            return hexString*/
        }
        return ""
    }
    
    /**
     * Converts NSData to a hex string
     */
    class func asHex(data: NSData) -> String {
        var resultAsHex: String = ""
        data.enumerateByteRangesUsingBlock({ (bytes, range, stop) -> Void in
            let chars = UnsafePointer<UInt8>(bytes)
            for i in 0...range.length-1 {
                resultAsHex += String(format: "%02x", UInt8(chars[i]))
            }
        })
        return resultAsHex
    }
    
    
    /**
     * Creates an NSData from a hex string
     *
     */
    class func dataFromHexadecimalString(input: String) -> NSData? {
        let trimmedString = input.stringByTrimmingCharactersInSet(NSCharacterSet(charactersInString: "<> ")).stringByReplacingOccurrencesOfString(" ", withString: "")
        
        // make sure the cleaned up string consists solely of hex digits, and that we have even number of them
        
        var error: NSError?
        _ = error
        let regex: NSRegularExpression?
        do {
            regex = try NSRegularExpression(pattern: "^[0-9a-f]*$", options: .CaseInsensitive)
        } catch let error1 as NSError {
            error = error1
            regex = nil
        }
        let found = regex?.firstMatchInString(trimmedString, options: [], range: NSMakeRange(0, trimmedString.characters.count))
        if found == nil || found?.range.location == NSNotFound || trimmedString.characters.count % 2 != 0 {
            return nil
        }
        
        // everything ok, so now let's build NSData
        
        let data = NSMutableData(capacity: trimmedString.characters.count / 2)
        
        for var index = trimmedString.startIndex; index < trimmedString.endIndex; index = index.successor().successor() {
            let byteString = trimmedString.substringWithRange(Range<String.Index>(start: index, end: index.successor().successor()))
            let num = UInt8(byteString.withCString { strtoul($0, nil, 16) })
            data?.appendBytes([num] as [UInt8], length: 1)
        }
        
        return data
    }
    

}