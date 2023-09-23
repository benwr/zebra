# Spartacus: an app for creating and verifying ring signatures
![](spartacus_desktop/spartacus_head.png)

## What are ring signatures?

Say you want to publish some information. You want people to know that it was
published by someone trustworthy, with access to that information, but you
don't want them to know exactly *who* published it. For example, it might be
information about someone's misconduct, and you fear retaliation.

You can publish the information using a ring signature. To do this, you choose
a set of people that you want to include in the "ring": This is the set of
people who, to an observer, *might* have published the information. Then, you
sign the message using *your* private key, and *their* public keys.

Once you publish the information with a ring signature, anyone who knows the
public keys of the ring members (you and the other people whose keys you used)
can tell that *someone* in that group signed the message. But they can't tell
*which* person it was.

## Design

Spartacus is intended to be as simple as possible, while being fairly paranoid
about storing secrets.

Spartacus is a [dioxus](https://dioxuslabs.com) app. This means that the user
interface code can be understood by anyone with knowledge of web programming,
but the app relies on the operating system's web view rather than a packaged
browser.

It uses [age](https://github.com/FiloSottile/age) to encrypt an extremely
simple database of keys. The password for this database is chosen randomly and
stored in the system's keychain. So the operating system will prompt the user
before allowing the database to be unlocked (on app start, or when modifying
the database or using a private key).

We try pretty hard to avoid exposing private keys to other apps. They aren't
stored in memory, except briefly when reading/writing the encrypted database,
or when performing a signing operation, or, of course, when explicitly sending
them to a new machine. When sending data to a remote machine, we use [Magic
Wormhole](https://github.com/magic-wormhole/magic-wormhole.rs) to ensure that
the transfer is encrypted end-to-end. We also use
[secmem-proc](https://github.com/niluxv/secmem-proc) to try to frustrate
attempts at tracing the process or reading core dumps / swap.

## Copyright Information

The icon file `spartacus_head.png` is a modification of ["Spartacus, marble
sculpture of Denis Foyatier (1830), Louvre
Museum"](https://www.flickr.com/photos/carolemage/8270400666) by Carole Raddato
on Flickr. Unlike the rest of this repository, it is released under a [Creative
Commons Attribution-ShareAlike 2.0 Generic
License](https://creativecommons.org/licenses/by-sa/2.0/).

Some of the code in this repository is released under an MIT license.
Specifically, everything inside of the `age` and `age-core` directories, as
well as the `sign` and `verify` functions in `spartacus_crypto/lib.rs`.

Everything else is the copyright of Kurt Brown.
