import process from 'process';
import { createRequire } from 'module';


const require = createRequire(import.meta.url);
const util = require('util');

let crypto;
var config =require('../config.json');

crypto = require('crypto');


/*
Tale metodo prende in input le VC e le VC i cui attributi sono criptati e restituisce gli attributi della VP decriptati
* @param VC, VP
* @return il valore degli attributi in chiaro della VP
*/
 export const verifyAttributes = async (VCs,VP)  => {

     const disclosedAttributes = VP.vp.attributes; // ottengo l'array di oggetti. Ogni oggetto è formato dalla tripla <attrName,key,iv>
    // console.log("credenziali")
    //  console.log(disclosedAttributes)
     for (const credential of VCs) { // per ogni credenziale
         var claims = credential.credentialSubject;
        /* console.log("gli attributi della credenziale sono ")
         console.log(claims)
         console.log("gli attributi della VP sono ")
         console.log(disclosedAttributes)*/
         if (claims && disclosedAttributes) { // se sono presenti sia i claims della VC da verificare che gli attributi della VP
             for (const element of disclosedAttributes) { // prendo la tripla dell'array
                 /*console.log("Nome attributo VC")
                console.log(claims)
                 console.log("attributi della VP")
                 console.log(element.attrName)
                 var attributes = element.attrName // Nome dell'attributo della VP
                 //console.log(element.attrName);
                 if(attributes===claims.attrName){
                     console.log("vero");
                 }*/
                // console.log("path")
                // console.log(element.path)
                 var {obj, propToVerify} = checkPath(element.path, claims); // recupero dalle claims delle VC, gli attributi presenti nella VP che voglio decifrare
                 // console.log("oggetto contenente seguenti info")
                 // console.log({obj, propToVerify})
                 var propertyPath = element.path.join('->');
                 // console.log("join "+propertyPath)
                 if(propToVerify){ // se è presente un valore da decifrare
                     let crypValAttr= propToVerify;
                     // console.log("valore criptato: " +propToVerify)
                     let key= element.key
                     // console.log("key: "+ key)
                     let iv = element.iv;
                     // console.log("iv: " + iv)
                     let decipher = crypto.createDecipheriv(config.symmetricKey.K, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex')); // creazione oggetto Decipher
                     decipher.update(Buffer.from(crypValAttr,'hex')); // update dell'attributo --> restituisce il buffer contenente l'attributo
                     let decrypted = Buffer.from(decipher.final()); // restituisce un buffer con il valore decifrato
                      // console.log("Il valore è " + decrypted.toString() );

                    //return  decrypted.toString();

                 }
             }
         }

     }
 }

const checkPath = (path, claims) => { // gli passo un array con un solo elemento [AttrNamei] e un oggetto di claims
    var finalProp = undefined;
    var object = {};
    path.forEach(element => {
        if(finalProp === undefined ) {
            finalProp = claims[element]; // trovo nell'oggetto il claims corrispondente al nome AttrName e prendo il suo valore
            object[element]=finalProp // inserisco il valore trovato in un oggetto  {element: valCriptato}
        }
        else {
            finalProp = finalProp[element];
        }
    });
    return {obj : object, propToVerify :finalProp}; // restituisco un oggetto contenente { obj {element: valCriptato} , il valore propToVerify cje contiene il valore criptato}
}