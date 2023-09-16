#![allow(non_snake_case)]

use dioxus::prelude::*;

fn main() {
    dioxus_desktop::launch(App);
}

fn App(cx: Scope) -> Element {
    cx.render(rsx! {
        section {
            TabSelect {}
        }
        section {
            class: "spartacus",
            style { include_str!("style.css") }
            About {}
        }
    })
}

fn TabSelect(cx: Scope) -> Element {
    cx.render(rsx! {
        nav {
            class: "tab_select",
            ol {
                li {
                    class: "tab_choice",
                    "My Keys"
                }
                li {
                    class: "tab_choice",
                    "Other Keys"
                }
                li {
                    class: "tab_choice",
                    "Sign"
                }
                li {
                    class: "tab_choice",
                    "Verify"
                }
            }
        }
    })
}

fn About(cx: Scope) -> Element {
    cx.render(rsx! {
        h1 {"Spartacus"}
        p {"A tool for ring signatures."}
        p {"Version 0.0.0"}
    })
}
