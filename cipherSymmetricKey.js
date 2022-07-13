import process from 'process';
import { createRequire } from 'module';


const require = createRequire(import.meta.url);
const util = require('util');

let crypto;
var config =require('../config.json');

try {
    crypto = require('crypto');
  //  let SymKey ;//= await crypto.getCipher();
    console.log("Available algorithms to encrypt are:");

    console.log(crypto.getCiphers());
}catch (err){
    console.log('crypto support is disabled');
    process.exit();
}


const generateKey = util.promisify(crypto.generateKey);

/*
* Tale metodo effettua la criptazione degli attributi delle VC
* @param attributo, chiave segreta, lunghezza chiave, algoritmo di cifratura
* @return <vettore di inizializzazione, attributo criptato, chiave segreta>
*/
export const SymmetricAttributes = async (attribute, key = undefined, Symmetrickeylength= config.symmetricKey.symmetrickeylength, type = config.symmetricKey.K)  => { // se non è specificata la chiave in input la creo, altrimenti prendo quella che do in input

    if(!key){
        key=crypto.randomBytes(Symmetrickeylength/8); //divido per 8 perché il parametro richiede i bytes e restituisce un buffer
    }

     let iv = crypto.randomBytes(16); // iv deve essere imprevedibile e unico e la sua lunghezza è di 16 bytes. Infatti i blocchi devono avere dimensione fissa di 16 bytes
    let cipher = crypto.createCipheriv(type, Buffer.from(key), Buffer.from(iv)); // restituisce un oggetto di tipo cipher
    cipher.update(Buffer.from(attribute)); // update dell'attributo --> restituisce il buffer contenente l'attributo

    let encrypted= Buffer.from(cipher.final()); // cripto l'attributo con cipher.final() --> il metodo final() restituisce un buffer

    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex'), keyAttr:key.toString('hex')}; //restituisce (iv, attrCriptato, chiave segreta)

}

