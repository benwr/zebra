#![allow(non_snake_case)]

use dioxus::prelude::*;

pub fn About(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
            class: "about",
            h1 {"Spartacus"}
            img {
                src: "../spartacus_head.png",
                height: "256px",
                width: "256px",
            }
            p {
                "(App Logo adapted from "
                a { 
                    href: "https://www.flickr.com/photos/carolemage/8270400666",
                    "Spartacus, marble sculpture of Denis Foyatier (1830), Louvre Museum"
                }
                " by Carole Raddato. Image is licensed under a "
                a {
                    href: "https://creativecommons.org/licenses/by-sa/2.0/",
                    "Creative Commons Attribution-ShareAlike 2.0 Generic License"
                }
                ")"
            }
            p {"A tool for creating and verifying ring signatures."}
            p {"Version 0.0.0"}
            p {"Copyright 2023 Ben Weinstein-Raun"}
        }
    })
}
