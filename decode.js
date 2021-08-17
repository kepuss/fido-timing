const base64url = require('base64url');

keyHandles = [
    "AW-HswK9-w0w77fyHmjGJGDJ_J6_IbZoQb3WaUbuT8e949qvVF61zdyYcziBlsDzVTszyO1UNozgPnSNEzDwNwg",
    "AWHzHVgH93XyA-AuDZe2hSO2oXmBNPRK4s7mpJqYfVr20xoyxmNu_vxg5jiTs4NlCirwVuv8SwwjxKlAm7dgPQ0",
"AdaLiwNNDO0HgQvYcD5x4m1JJktJ-UZvvXqwKqdTFljrzqLsYHyrA7b9W1Qxqechmt_vZasBr3yvgcrQ5Zo_n0U",
"AZK_uePJ0gqL_82W2hkbh5gL5pLbLHjC8pS_IlF6b375k4EEXJWp6GurclncYWj24K5Rz0plpmzz6IbbYdr_n1Y",
    "ziTYQibTrA5GS4-6P6NfqHOaV-KdeevP6P-p7QnrexeJRocIRwYDti9an6lGdkCahFTBmBWi4XDoCe6UfNcadw"

]

for(handle of keyHandles) {
    var buffer = base64url.toBuffer(handle)
    console.log(buffer.toString('hex'))
}

// Array.prototype.insert = function ( index, item ) {
//     this.splice( index, 0, item );
// };
//
// var arr = [ 'A', 'B', 'D', 'E','F','G','I' ];
//
// var limit = arr.length
// for( var i =1; i<limit*2;i=i+2){
//     arr.insert(i,"X")
// }
//
// console.log(arr)