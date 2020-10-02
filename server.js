var graphene = require("graphene-pk11");
var fs = require('fs');
var Module = graphene.Module;
 
var lib = "C:/Windows/System32/SignatureP11.dll";
 
var mod = Module.load(lib, "PROXKey Module");
mod.initialize();
 
var slot = mod.getSlots(0);
if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
    var session = slot.open();
    session.login("12345678");
    
    // generate RSA key pair
    var keys = session.generateKeyPair(graphene.KeyGenMechanism.RSA, {
        keyType: graphene.KeyType.RSA,
        modulusBits: 1024,
        publicExponent: Buffer.from([3]),
        token: false,
        verify: true,
        encrypt: true,
        wrap: true
    }, {
        keyType: graphene.KeyType.RSA,
        token: false,
        sign: true,
        decrypt: true,
        unwrap: true
    });
    
    //PDF Sign
    let pdf = fs.readFileSync("dummy.pdf");
    const lastChar = pdf.slice(pdf.length - 1).toString();
        if (lastChar === '\n') {
            // remove the trailing new line
            pdf = pdf.slice(0, pdf.length - 1);
        }

    // sign content
    var sign = session.createSign("SHA1_RSA_PKCS", keys.privateKey);
    sign.update(pdf.toString('binary'));
    var signature = sign.final();
    console.log("Signature RSA-SHA1:", signature.toString("hex")); 
    
    // verify content
    var verify = session.createVerify("SHA1_RSA_PKCS", keys.publicKey);
    verify.update(pdf.toString('binary'));
    var verify_result = verify.final(signature);
    console.log("Signature RSA-SHA1 verify:", verify_result);      // Signature RSA-SHA1 verify: true
    
    session.logout();
    session.close();
}
else {
    console.error("Slot is not initialized");
}
 mod.finalize();