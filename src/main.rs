#![allow(non_snake_case)]

use dioxus::prelude::{rsx, Scope, Element, dioxus_elements};

fn main() {
    dioxus_desktop::launch(App);
}

fn App(cx: Scope) -> Element {
    cx.render(rsx! {
        div { "SPARTACVSSVM" }
    })
}
