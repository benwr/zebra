#![allow(non_snake_case)]

use dioxus::prelude::{Element, Scope, dioxus_elements, fc_to_builder, rsx};

fn main() {
    dioxus_desktop::launch(App);
}

fn App(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
            "style": "font-family: sans-serif;",
            About {}
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
