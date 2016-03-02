//
//  MD5Generator.swift
//  AES Sample
//
//  Created by ryan teixeira on 3/1/16.
//  Copyright © 2016 Ryan Teixeira. All rights reserved.
//

import Foundation

class MD5Generator {
    func md5(input: String) -> String {
        //var s = "The quick brown fox jumps over the lazy dog."
        
        let context = UnsafeMutablePointer<CC_MD5_CTX>.alloc(1)
        var digest = Array<UInt8>(count:Int(CC_MD5_DIGEST_LENGTH), repeatedValue:0)
        
        CC_MD5_Init(context)
        CC_MD5_Update(context, input,
            CC_LONG(input.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)))
        CC_MD5_Final(&digest, context)
        context.dealloc(1)
        let hexString = Hex.asHex(digest)
        print(hexString)
        return hexString
    }
}

