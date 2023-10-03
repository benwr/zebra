#![allow(non_snake_case)]

use dioxus::prelude::*;

pub fn About(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
            class: "about",
            h1 {"Spartacus"}
            p {"Version 1.0.0-alpha"}
            p {"A tool for creating and verifying ring signatures."}
            p {
                class: "copyright_info",
                "App Logo adapted from "
                a {
                    href: "https://www.flickr.com/photos/carolemage/8270400666",
                    "Spartacus, marble sculpture of Denis Foyatier (1830), Louvre Museum"
                }
                " by Carole Raddato. Image is licensed under a "
                a {
                    href: "https://creativecommons.org/licenses/by-sa/2.0/",
                    "Creative Commons Attribution-ShareAlike 2.0 Generic License"
                }
            }
            p {
                class: "copyright_info",
                "All other content is written by Ben Weinstein-Raun; copyright assigned to Kurt Brown. Source code available at "
                a {
                    href: "https://github.com/benwr/spartacus",
                    "https://github.com/benwr/spartacus"
                }
            }
        }
    })
}
