const crypto = require("crypto");
const algorithm = "aes-192-cbc";

const iv = new Uint8Array(16);
const salt = "pepper";

module.exports = function encrypt(text, pwd) {
    let key = crypto.scryptSync(pwd, salt, 24);
    let cipher = crypto.createCipheriv(algorithm, key, iv);
    return cipher.update(text, "utf8", "base64") + cipher.final("base64");
};


const decrypt = (hash, pwd) => {
    let key = crypto.scryptSync(pwd, salt, 24);
    const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(iv, 'hex'));

    const decrpyted = Buffer.concat([decipher.update(Buffer.from(hash, 'base64')), decipher.final()]);

    return decrpyted.toString();
};

console.log(decrypt("lCUm7e75Or8z09Fgv4CUHsXa3dXyXk6lPW6KJ8NF+qk=","pizza"))
