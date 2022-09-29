
import * as X25519 from "curve25519-js";
import * as crypto from 'crypto'
import * as base64 from 'base64-js'
import blake2b from "blake2b";
import { zlib } from "zlib-wasm";
const subtle = crypto.webcrypto.subtle;
export class EC{
    toHex(arr:Uint8Array){
        let strArr = []  as  string[]
        arr.forEach(e=>{let s = e.toString(16) ;strArr.push(s.length == 1 ? '0' + s : s)})
        return strArr.join("")
    }
    async genRandomKeyBuffer(length:number = 32):Promise<Uint8Array>{
        let p = {
            name:'HMAC',
            hash:'SHA-512',
            length:256
        }
        let keyObj = await subtle.generateKey(p,true,['sign']) as  CryptoKey
        let keyBf = await subtle.exportKey('raw',keyObj);
        keyObj = await subtle.importKey('raw',keyBf,'PBKDF2',false,['deriveKey'])
        
        let salt = crypto.webcrypto.getRandomValues(new Uint8Array(64));
        let pbkdf2 = {
            name:"PBKDF2",
            hash:"SHA-512",
            iterations:10,
            salt:  salt.buffer  
        }
        let dk = {
            name: "HMAC",
            hash: "SHA-512",
            length:length * 8,
        }
        let result  = await subtle.deriveKey(pbkdf2,keyObj,dk,true,['sign']);

        return new Uint8Array(await subtle.exportKey('raw',result))
    }

    async generateNewKeyPair(): Promise<{private:string,public:string}>{
        let a = await this.genRandomKeyBuffer();
        let kp = X25519.generateKeyPair(a);
        let kp2 = {
            public:base64.fromByteArray(kp.public),
            private:base64.fromByteArray(kp.private)
        }
        return kp2
    }
    async decrypt(privateKeyB64:string,data:Uint8Array){
        if (!(data[0] == 4 || data[0] == 5)) {
            throw "data format not support"
        }
        let privateKey = base64.toByteArray(privateKeyB64);
        let iv = data.subarray(8,24)
        let mac = data.subarray(24,56);
        let tmpPub = data.subarray(56,88);
        let enc = data.subarray(88)
        let dh = X25519.sharedKey(privateKey,tmpPub);

        let kp = X25519.generateKeyPair(privateKey);
        let hash64 = new Uint8Array(64);
        this.hashDH(dh,kp.public,tmpPub,hash64);

        

        let b2b = blake2b(32,hash64.subarray(32,64))
        b2b.update(iv)
        b2b.update(tmpPub)
        b2b.update(enc);

        let mac2 = b2b.digest('binary')
        for (let i = 0; i < 32; i++) {
            if (mac[i] != mac2[i]) {
                throw "MAC NOT FIT"
            }
        }
 

        return this.aesDecrypt(hash64.subarray(0,32),iv,enc);

    }

    private hashDH(dh:Uint8Array,pub1:Uint8Array,pub2:Uint8Array,dh64:Uint8Array){

        let shared96 = new Uint8Array(96)
        dh.forEach((e ,i)=>{
            shared96[i] = e;
        })
        /// compare pub
        let flag = 0;
        for (let i = 63; i >= 0; --i) {
            const element = pub1[i];
            const element2 = pub2[i];
            if (element < element2) {
                flag = -1;
                break;
            }else if(element > element2){
                flag = 1;
                break;
            }
        }
        if (flag == -1) {
            pub1.forEach((e ,i)=>{
                shared96[i + 32] = e;
            })
            pub2.forEach((e ,i)=>{
                shared96[i + 64] = e;
            })
        }else{
            pub2.forEach((e ,i)=>{
                shared96[i + 32] = e;
            })
            pub1.forEach((e ,i)=>{
                shared96[i + 64] = e;
            })
        }

        let r = blake2b(64).update(shared96).digest('binary')
        r.forEach((e,i)=>{dh64[i] = e});
        shared96.fill(0);
        r.fill(0);
    }

    async encrypt(pubBase64:string,data:Uint8Array,isZipData:boolean = true){
        let pubKey = base64.toByteArray(pubBase64);
        if (pubKey.length != 32) {
            throw "pubkey length error"
        }
        let a = await this.genRandomKeyBuffer(32);
        let kp = X25519.generateKeyPair(a);
        let dh = X25519.sharedKey(kp.private,pubKey);

        let hash2 = new Uint8Array(64);
        this.hashDH(dh,pubKey,kp.public,hash2)
        kp.private.fill(0)

        
        // b2b.update('')
        let key = hash2.subarray(0,32)
        let iv = await crypto.webcrypto.getRandomValues(new Uint8Array(16))
        let enc = await this.aesEncrypt(key,iv,data)
        var tmpPub = kp.public
        let b2b = blake2b(32,hash2.subarray(32,64));
        b2b.update(iv)
        b2b.update(tmpPub)
        b2b.update(enc);
        let mac = b2b.digest('binary')

        let result = new Uint8Array(8 + mac.length + iv.length + tmpPub.length + enc.length )
        result[0]= isZipData ? 4 : 5;
        result[1]= 0
        result[2]= 16;
        result[3]= 0;
        result[4]= 32;
        result[5]= 0;
        result[6]= 32;
        result[7]= 0;


        let start = 8;
        result.set(iv,start)
        start += iv.length;
        result.set(mac,start)
        start += mac.length
        result.set(tmpPub,start)
        start += tmpPub.length
        result.set(enc,start)

        return result
    }

    async aesDecrypt(key:Uint8Array,iv:Uint8Array,data:Uint8Array):Promise<Uint8Array>{
        let p = {
            name:'AES-CBC',
            iv:iv,
        }
        let keyObj = await subtle.importKey('raw',key,'AES-CBC',false,['decrypt']);

        return  new Uint8Array(await subtle.decrypt(p,keyObj,data));
    }
    async aesEncrypt(key:Uint8Array,iv:Uint8Array,data:Uint8Array):Promise<Uint8Array>{
        let p = {
            name:'AES-CBC',
            iv:iv,
        }
        let keyObj = await subtle.importKey('raw',key,p,false,['encrypt']);
        return new  Uint8Array(await subtle.encrypt(p,keyObj,data));
    }

 
}