#![allow(non_snake_case)]

use dioxus::prelude::{Element, Scope, dioxus_elements, rsx};

fn main() {
    dioxus_desktop::launch(App);
}

fn App(cx: Scope) -> Element {
    cx.render(rsx! {
        div { "SPARTACVSSVM" }
    })
}
