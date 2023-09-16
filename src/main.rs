#![allow(non_snake_case)]

use dioxus::prelude::*;

fn main() {
    dioxus_desktop::launch(App);
}

#[derive(Clone, Debug)]
enum ActiveTab {
    MyKeys,
    OtherKeys,
    Sign,
    Verify,
    About,
}

fn App(cx: Scope) -> Element {
    use dioxus_desktop::tao::dpi::{LogicalSize, Size};
    let desktop = dioxus_desktop::use_window(cx);
    desktop.set_title("Spartacus");
    desktop.set_min_inner_size(Some(Size::Logical(LogicalSize{width: 640.0, height: 256.0})));

    use_shared_state_provider(cx, || ActiveTab::MyKeys);

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

fn TabSelect(cx: Scope) -> Element {
    let desktop = dioxus_desktop::use_window(cx);
    let active_tab = use_shared_state::<ActiveTab>(cx).unwrap();
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

fn MyKeys(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
        }
    })
}

fn OtherKeys(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
        }
    })
}

fn Sign(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
        }
    })
}

fn Verify(cx: Scope) -> Element {
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
