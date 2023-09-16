#![allow(non_snake_case)]

use dioxus::prelude::*;

fn main() {
    dioxus_desktop::launch(App);
}

fn App(cx: Scope) -> Element {
    use dioxus_desktop::tao::dpi::{LogicalSize, Size};
    let desktop = dioxus_desktop::use_window(cx);
    desktop.set_title("Spartacus");
    desktop.set_min_inner_size(Some(Size::Logical(LogicalSize{width: 640.0, height: 256.0})));
    cx.render(rsx! {
        section {
            class: "spartacus",
            style { include_str!("style.css") }
            TabSelect {}
            div {
                class: "contents",
                About {}
            }
        }
    })
}

#[derive(Clone, Debug)]
enum SelectedTab {
    MyKeys,
    OtherKeys,
    Sign,
    Verify,
    About,
}

fn TabSelect(cx: Scope) -> Element {
    let desktop = dioxus_desktop::use_window(cx);
    cx.render(rsx! {
        nav {
            onmousedown: move |_| { desktop.drag(); },
            class: "tab_select",
            div {
                class: "tab_choice inactive_tab",
                "My Keys"
            }
            div {
                class: "tab_choice inactive_tab",
                "Other Keys"
            }
            div {
                class: "tab_choice inactive_tab",
                "Sign"
            }
            div {
                class: "tab_choice inactive_tab",
                "Verify"
            }
            div {
                class: "tab_choice active_tab",
                "About"
            }
        }
    })
}

fn Sign(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
        }
    })
}

fn About(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
            class: "about",
            h1 {"Spartacus"}
            p {"A tool for creating and verifying ring signatures."}
            p {"Version 0.0.0"}
        }
    })
}
