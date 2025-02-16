const decode_me = "dX9ydEhnWwBsfQBEbHBBSkNHA2xeBxdHAEFO";
var b64_decoded = atob(decode_me).split("");
for (let pin = 0; pin < 10; pin++) {
  var decoded = [...b64_decoded];
  for (let i = 0; i < b64_decoded.length; i++) {
    decoded[i] = String.fromCharCode(
      b64_decoded[i].charCodeAt(0) ^ pin.toString().charCodeAt(0)
    );
  }
  console.log("Using pin " + pin + " : " + decoded.join(""));
}
