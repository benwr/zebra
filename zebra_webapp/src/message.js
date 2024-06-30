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
    const messageString = `
The following message has been signed using Zebra 1.0:
"""
Sam Altman is not consistently candid
"""

It was signed by someone with a private key corresponding to one of these fingerprints:

adam scholl <> I{*Lp^cWy3 PHKEz&w/h1 -!}cRRMRX: po}24=xJ*<
Locke <locke@jpwiggin.nets> F:BPLhL[#D BPM%IKD17A u>@0LZWh7l dL}+qd4a[y
Demosthenes <demosthenes@jpwiggin.nets> [K.60l#{^D +(naR&*iu? 7xn7MBL[0V CRM?sR*-=&
peter <> VB85{Ra3:G ]QdDn7tU>Z E<00ZFg.Jr WzF3sO]mZJ
kb test key 5 <kbstest5@email.com> lC}q7>.EJv rSQ9wc(VNP HqO96gu83W Juw}Ksbkza
Steve <> qa<e<2b(4g P+ja5I%N#S !W+*a!M$I( W#$jtkw+^=
sid <> wb}{gh$g0> Drg1KOy]u3 {vc1[)sQ)9 ThU<O.D{/D

PKncuq%tJKiFtRk?vvhcVS$lFQ%RRt1ItgdKbRo[2lj-73JHebvpS!-aAI4az!%j&0000%/VD0&hkNt1aP13{kE:1XA<(}Kcjn7n2#fK!<DhRnG*5KfRVeR$i1r9j/yV0@{{rT3ZVC/f+?M-q*1DGd0000%/VD0&hkNt1aP13{kE:1XA<(}Kcjn7n2#fK!<DhTEDAUmfZ<yPHtSVHn?+OXZZR:%[-a/:z2v/d([zjCH^Oq!1.*YJXk\${^#&<(uw.!MUG?HsIH!i!-4o{2R-0000)z!0M]6951jy&r*0wK70HCwgY5x(kLvwPS0Brzmj[]a@0h&tE*k*Gv&(BvDj3NO>N3ZK&(Le]UnA!M@e*0t4f70JI$sqLXMB1?dJFDSmGrd?/9q<Z58>0001Jrzmj[]a@0h&tE*k*Gv&(BvDj3NO>N3ZK&(Le]Ungt?(oj0kFghFv)!fVwY#3h1^y5gk>?IoNde#Xe2IOepbB]eVM>aTPyRA}K-tIfnCqC3n+SAsYFvXi8oR:0000!wO(vbBzbl6wPFZ?003LvzeTGqxK#6)B3KFVCwgY5x(kLvwPS0V8nMym2:zJiO$ITT1>mzXr&Os:1-+[Z3R)H%.p-d1]Q/b2AZ^XUFFpi:A2Ir7}TLD0angghKAiozeozs40001+8nMym2:zJiO$ITT1>mzXr&Os:1-+[Z3R)H%.p-ccDHTCe1rl8&-2M@)h8KhSsit8&?o*fZzBYEVB7L)cFHB[4.)1.epSbs(LV4$B](?9HMBoZ?@&aMw3TTey0001rwPRH700000WKt!uLH[/?(%S.u(O%IBD(*wF1d(S5DsSWYWXaurIiizm0-f[$hEv1pZz91x.hBJxxnI#{>aQ=TOZTnn0rr91WKt!uLH[/?(%S.u(O%IBD(*wF1d(S5DsSWYWXaurT{YqC+OCnoPpV*-qO#-#R6&Stz&Y0h/@i32C8yCCB3vVw{C=@jDy0e)}hPyudnCd1/9GjC&RWDoWsx?o4fcwdyHOAdwPI@oyH}=lh4/(?0bD4+By/Jnh9+.&vqfKgv@Dkd+&kc<Gm:QLldf!PQ8tV[PU*t^Oh5!*r%}RQ6K?By4-[PCu%9er*p#4qu^JQo3)kaQ<hwWb7jt7vJDbHf0002y+&kc<Gm:QLldf!PQ8tV[PU*t^Oh5!*r%}RQ6K?AIOeo=85l&bK}h<n5b4>-DuOkijdsuN[Z^Dnob4Q&1tCrmYAD=:1H8?}rM3zG4p1koEhQ2=T-/AOjDCoW*0000$By/Sb00000>/{7zg<1rB/xum%06Uc41d]hn&zMZOG:5zKri.l3O>/Ybl^wC%mY>TSg(thT(pEJESee$EZx&KaRq3Uf0rr91>/{7zg<1rB/xum%06Uc41d]hn&zMZOG:5zKri.l3l&H&x79{ykJRyvDO4rVljcno*9FLJ/N//(=d5HqUhPNDwk2#.Wtg5HAfKI[{lKRuGD$&R$A<eRR7CV9$0@@r3B7]d+0002!nX9DH=h?Z0BnC.l&N4L}OG]abn$8ciKE6*]CI2B1=C$-fw<u.vOq.Qo*f4j(DNBL$LB[!P&A5xj{GO4a0002!nX9DH=h?Z0BnC.l&N4L}OG]abn$8ciKE6*]CI2AApDKkc86YOpNk*hBiSw{A8lZ<ZZEjk}BTmy[Dv2@q9m2q}Q%6ZH<?}c4O&0]-cQAcG%8&c3*xl]J#9)5B

To verify this signature, paste this entire message into the Zebra app (starting with "The following message" and ending with this line).
    `;

    try {
        const signedMessage = SignedMessage.fromString(messageString);
        console.log(signedMessage.verify());
    } catch (error) {
        console.error(error.message);
    }
}