import naclUtil from 'tweetnacl-util';
import z85 from 'z85';

const SIGNED_MESSAGE_FIRST_LINE = "The following message has been signed using Zebra 1.0:";
const SIGNED_MESSAGE_SECOND_LINE = "\"\"\"";
const SIGNED_MESSAGE_SUFFIX_FIRST_LINE = "";
const SIGNED_MESSAGE_SUFFIX_SECOND_LINE = "To verify this signature, paste this entire message into the Zebra app (starting with \"The following message\" and ending with this line).";

class PublicKey {
    constructor(holder, keypoint) {
        this.holder = holder;
        this.keypoint = keypoint;
    }

    static fromString(str) {
        // Implement parsing logic if needed
    }

    validateAttestation() {
        // Implement validation logic if needed
    }

    fingerprint() {
        // Implement fingerprint logic if needed
    }
}

class SignedMessage {
    constructor(message, challenge, ring) {
        this.message = message;
        this.challenge = challenge;
        this.ring = ring;
    }

    static fromString(s) {
        const lines = s.trim().split('\n');
        if (lines.length < 12) {
            throw new Error("ParseError: The shortest allowed signed message has 12 lines.");
        }

        console.log(lines[lines.length - 3])

        const signatureBytes = z85.decode(lines[lines.length - 3]);
        const challenge = signatureBytes.subarray(0, 32);
        const ring = [];

        console.log("let's start ring")

        for (let i = lines.length - 5; i >= 5; i--) {
            const [name, email, fingerprint] = lines[i].split(' ');
            console.log(fingerprint)
            const holder = { name, email };
            const keypoint = naclUtil.decodeBase64(fingerprint);
            console.log("let's push ring")
            ring.push([new PublicKey(holder, keypoint), signatureBytes.subarray(32 + (i - 5) * 32, 64 + (i - 5) * 32)]);
        }

        console.log("ring done")

        const message = lines.slice(2, lines.length - 5 - ring.length - 3).join('\n');

        return new SignedMessage(message, challenge, ring);
    }

    verify() {
        for (const [k, _] of this.ring) {
            if (!k.validateAttestation()) {
                return false;
            }
        }

        return this.signature().verify(naclUtil.decodeUTF8(this.message));
    }

    signature() {
        return {
            challenge: this.challenge,
            ring_responses: this.ring.map(([k, s]) => [k.keypoint, s])
        };
    }
}

export default function testMessage() {
    const messageString = `The following message has been signed using Zebra 1.0 Beta:
"""
The real question we should be asking: WHY is the earth round? WHY is it not flat?
"""

It was signed by someone with a private key corresponding to one of these fingerprints:

Simon <simon.mailadres@gmail.com> lm6vDv.wlx vk?(=-K?I( Qn[hI16UYZ Pr7YpyG5?U

5qA-hkhEeVk=m#ljjN2GpK-p3^vCVMTA2E91.LTP0rr911POJ5q!Z8!zw-AO0cq<>z/dgAvqfK^wo8m5kXB}xx(2ziz/2GI(fXVic!!L!DTQ1tU5viP9.Os%h9N2L.EAX.-6FbiV&/T&POT!$i0NePr4bn/=$z*3?}R7i)l1y^?*+}j0001{(fXVic!!L!DTQ1tU5viP9.Os%h9N2L.EAX.-6F8v1odLn<NXBJ5w0L4Uw17ifX@Z2]8v?b{{o?fgVw+2}dfVB*=>-S}*$*Hkz=gZz0LxO^ya0lRSUE-#6dK>

To verify this signature, paste this entire message into the Zebra app (starting with "The following message" and ending with this line).
`;

    try {
        const signedMessage = SignedMessage.fromString(messageString);
        console.log(signedMessage.verify());
    } catch (error) {
        console.error(error.message);
    }
}