import * as wasm from "zebra_wasm";

const messageString = `The following message has been signed using Zebra 1.0 Beta:
"""
The real question we should be asking: WHY is the earth round? WHY is it not flat?
"""

It was signed by someone with a private key corresponding to one of these fingerprints:

Simon <simon.mailadres@gmail.com> lm6vDv.wlx vk?(=-K?I( Qn[hI16UYZ Pr7YpyG5?U

5qA-hkhEeVk=m#ljjN2GpK-p3^vCVMTA2E91.LTP0rr911POJ5q!Z8!zw-AO0cq<>z/dgAvqfK^wo8m5kXB}xx(2ziz/2GI(fXVic!!L!DTQ1tU5viP9.Os%h9N2L.EAX.-6FbiV&/T&POT!$i0NePr4bn/=$z*3?}R7i)l1y^?*+}j0001{(fXVic!!L!DTQ1tU5viP9.Os%h9N2L.EAX.-6F8v1odLn<NXBJ5w0L4Uw17ifX@Z2]8v?b{{o?fgVw+2}dfVB*=>-S}*$*Hkz=gZz0LxO^ya0lRSUE-#6dK>

To verify this signature, paste this entire message into the Zebra app (starting with "The following message" and ending with this line).
`;

console.log(messageString)

const isValid = wasm.verify_signature(messageString);
console.log(`Signature is valid: ${isValid}`);
