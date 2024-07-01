import { decode as z85decode } from 'z85';
import { deserialize } from 'borsh';

// Define the schema for Scalar and PublicKey
class Scalar {
    constructor({ value }) {
        this.value = value;
    }
}

class PublicKey {
    constructor({ key }) {
        this.key = key;
    }
}

// Define the schema for the tuple (Scalar, Vec<(PublicKey, Scalar)>)
class Signature {
    constructor({ challenge, ring }) {
        this.challenge = challenge;
        this.ring = ring;
    }
}

// Define the Borsh schema
const schema = {
    Scalar: { kind: 'struct', fields: [['value', 'u32']] },
    PublicKey: {
        kind: 'struct',
        fields: [
            ['holder', { kind: 'struct', fields: [['name', 'string'], ['email', 'string']] }],
            ['version', 'string'],
            ['keypoint', { kind: 'array', type: 'u8', length: 32 }],
            ['holderAttestation', { kind: 'array', type: 'u8', length: 64 }]
        ]
    },
    Signature: {
        kind: 'struct',
        fields: [
            ['challenge', 'Scalar'],
            ['ring', { kind: 'array', type: { kind: 'tuple', fields: ['PublicKey', 'Scalar'] } }]
        ]
    }
};


// Define constants
const SIGNED_MESSAGE_FIRST_LINE = "The following message has been signed using Zebra 1.0 Beta:";
const SIGNED_MESSAGE_SECOND_LINE = '"""';
const SIGNED_MESSAGE_INFIX_FIRST_LINE = '"""';
const SIGNED_MESSAGE_INFIX_SECOND_LINE = "";
const SIGNED_MESSAGE_INFIX_THIRD_LINE = "It was signed by someone with a private key corresponding to one of these fingerprints:";
const SIGNED_MESSAGE_INFIX_FOURTH_LINE = "";
const SIGNED_MESSAGE_SUFFIX_FIRST_LINE = "";
const SIGNED_MESSAGE_SUFFIX_SECOND_LINE = "To verify this signature, paste this entire message into the Zebra app (starting with \"The following message\" and ending with this line).";

export class SignatureParseError extends Error {
  constructor(message) {
    super(message);
    this.name = "SignatureParseError";
  }

  static ParseError() {
    return new SignatureParseError("Parse Error");
  }

  static NotParseError(code) {
    return new SignatureParseError(`Not Parse Error: ${code}`);
  }
}

export class SignedMessage {
  constructor(message, challenge, ring) {
    this.message = message;
    this.challenge = challenge;
    this.ring = ring;
  }

  static fromString(s) {
    const lines = s.trim().split('\n');
    if (lines.length < 12) {
      throw SignatureParseError.ParseError();
    }

    // Check the fixed prefix (lines 0 and 1)
    if (lines[0] !== SIGNED_MESSAGE_FIRST_LINE || lines[1] !== SIGNED_MESSAGE_SECOND_LINE) {
      throw SignatureParseError.ParseError();
    }

    // Check the fixed suffix (lines M+5+N+3 and M+5+N+4; a.k.a. lines.len() - 2 and
    // lines.len() - 1. Then, also check the blank line before the signature data (M+5+N+1 =
    // lines.len() - 3)
    if (
      lines[lines.length - 1] !== SIGNED_MESSAGE_SUFFIX_SECOND_LINE ||
      lines[lines.length - 2] !== SIGNED_MESSAGE_SUFFIX_FIRST_LINE ||
      lines[lines.length - 4] !== ""
    ) {
      throw SignatureParseError.ParseError();
    }

    // Extract data from the signature line (line M+5+N+2 = lines.len() - 3)
    let signatureBytes;
    try {
      signatureBytes = z85decode(lines[lines.length - 3]);
    } catch (e) {
      throw SignatureParseError.ParseError();
    }

    console.log(signatureBytes.toString());

    const signature = deserialize(schema, Signature, signatureBytes);
    console.log(signature)

    let challenge, ring;
    try {
      // Assuming you have a way to deserialize into [Scalar, Vec<(PublicKey, Scalar)>] tuple
      // This is just a placeholder, adapt as per your deserializer's API
      [challenge, ring] = deserializeSignatureData(signatureBytes);
    } catch (e) {
      throw SignatureParseError.ParseError();
    }

    // Verify that the ring in the signature data exactly matches the data in the text:
    // (lines M+5+1 through M+5+N; a.k.a. lines.len() - 5 - (N - 1) through lines.len() - 5)
    for (let i = 0; i < ring.length; i++) {
      const [signer, _] = ring[ring.length - 1 - i];
      const line = formatSigner(signer);

      if (lines[lines.length - 5 - i] !== line) {
        throw SignatureParseError.ParseError();
      }
    }

    // Check the fixed lines between the ring info and the message
    if (
      lines[lines.length - 5 - ring.length] !== SIGNED_MESSAGE_INFIX_FOURTH_LINE ||
      lines[lines.length - 5 - ring.length - 1] !== SIGNED_MESSAGE_INFIX_THIRD_LINE ||
      lines[lines.length - 5 - ring.length - 2] !== SIGNED_MESSAGE_INFIX_SECOND_LINE ||
      lines[lines.length - 5 - ring.length - 3] !== SIGNED_MESSAGE_INFIX_FIRST_LINE
    ) {
      throw SignatureParseError.ParseError();
    }

    return new SignedMessage(
      lines.slice(2, lines.length - 5 - ring.length - 3).join("\n"),
      challenge,
      ring
    );
  }
}

function deserializeSignatureData(signatureBytes) {
  // Placeholder function for deserialization, replace with actual deserialization logic
  // Should return a tuple [challenge, ring]
  return [];
}

function formatSigner(signer) {
  return `${signer.holder.name} <${signer.holder.email}> ${signer.fingerprint()}`;
}

export default function testMessage3() {
    const messageString = `The following message has been signed using Zebra 1.0 Beta:
"""
The real question we should be asking: WHY is the earth round? WHY is it not flat?
"""

It was signed by someone with a private key corresponding to one of these fingerprints:

Simon <simon.mailadres@gmail.com> lm6vDv.wlx vk?(=-K?I( Qn[hI16UYZ Pr7YpyG5?U

5qA-hkhEeVk=m#ljjN2GpK-p3^vCVMTA2E91.LTP0rr911POJ5q!Z8!zw-AO0cq<>z/dgAvqfK^wo8m5kXB}xx(2ziz/2GI(fXVic!!L!DTQ1tU5viP9.Os%h9N2L.EAX.-6FbiV&/T&POT!$i0NePr4bn/=$z*3?}R7i)l1y^?*+}j0001{(fXVic!!L!DTQ1tU5viP9.Os%h9N2L.EAX.-6F8v1odLn<NXBJ5w0L4Uw17ifX@Z2]8v?b{{o?fgVw+2}dfVB*=>-S}*$*Hkz=gZz0LxO^ya0lRSUE-#6dK>

To verify this signature, paste this entire message into the Zebra app (starting with "The following message" and ending with this line).
`;

  const signedMessage = SignedMessage.fromString(messageString);
        console.log(signedMessage.verify());
}

