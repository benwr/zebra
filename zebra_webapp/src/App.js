import React, { useEffect } from "react";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import crypto from "crypto-browserify";
import testMessage from "./message";
import testMessage3 from "./message3";

function hashMessageAndRing(message, keys) {
  const hash = crypto.createHash('sha512');
  hash.update(message);
  keys.forEach(key => {
      hash.update(key);
  });
  return hash;
}

class Signature {
  constructor(challenge, ringResponses) {
      this.challenge = challenge;
      this.ringResponses = ringResponses;
  }

  verify(message) {
      const initialHash = hashMessageAndRing(message, this.ringResponses.map(([k, _]) => k));
      let reconstructedChallenge = this.challenge;

      for (const [keypoint, response] of this.ringResponses) {
          const h = initialHash.copy();
          const hashUpdate = nacl.scalarMult.base(response).map((v, i) => v + nacl.scalarMult(reconstructedChallenge, keypoint)[i]);
          h.update(hashUpdate);
          reconstructedChallenge = naclUtil.decodeBase64(h.digest('base64'));
      }

      return naclUtil.encodeBase64(this.challenge) === naclUtil.encodeBase64(reconstructedChallenge);
  }
}

function testEncrypt() {
  const message = naclUtil.decodeUTF8("example message");
  const challenge = new Uint8Array(32);  // Replace with actual challenge
  const ringResponses = [[new Uint8Array(32), new Uint8Array(32)]];  // Replace with actual ring responses
  
  const signature = new Signature(challenge, ringResponses);
  console.log(signature.verify(message));
}

function App() {
  useEffect(() => {
    testMessage3();
  }, []);
  return (
    <div>
      <h1>Zebra</h1>
    </div>
  );
}

export default App;
