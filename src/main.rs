#![allow(non_snake_case)]

use dioxus::prelude::*;

fn main() {
    dioxus_desktop::launch(App);
}

#[derive(Clone, Copy, Debug)]
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
                {
                    match *use_shared_state::<ActiveTab>(cx).unwrap().read() {
                        ActiveTab::MyKeys => rsx! { MyKeys {} },
                        ActiveTab::OtherKeys => rsx! { OtherKeys {} },
                        ActiveTab::Sign => rsx! { Sign {} },
                        ActiveTab::Verify => rsx! { Verify {} },
                        ActiveTab::About => rsx! { About {} },
                    }
                }
            }
        }
    })
}

fn TabSelect(cx: Scope) -> Element {
    let desktop = dioxus_desktop::use_window(cx);
    let active_tab = *use_shared_state::<ActiveTab>(cx).unwrap().read();
    cx.render(rsx! {
        nav {
            onmousedown: move |_| { desktop.drag(); },
            class: "tab_select",
            div {
                onclick: move |_| {*use_shared_state::<ActiveTab>(cx).unwrap().write() = ActiveTab::MyKeys},
                class: {
                    if let ActiveTab::MyKeys = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                "My Keypairs"
            }
            div {
                onclick: move |_| {*use_shared_state::<ActiveTab>(cx).unwrap().write() = ActiveTab::OtherKeys},
                class: {
                    if let ActiveTab::OtherKeys = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                "Other Keys"
            }
            div {
                onclick: move |_| {*use_shared_state::<ActiveTab>(cx).unwrap().write() = ActiveTab::Sign},
                class: {
                    if let ActiveTab::Sign = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                class: "tab_choice inactive_tab",
                "Sign"
            }
            div {
                onclick: move |_| {*use_shared_state::<ActiveTab>(cx).unwrap().write() = ActiveTab::Verify},
                class: {
                    if let ActiveTab::Verify = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                class: "tab_choice inactive_tab",
                "Verify"
            }
            div {
                onclick: move |_| {*use_shared_state::<ActiveTab>(cx).unwrap().write() = ActiveTab::About},
                class: {
                    if let ActiveTab::About = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                "About"
            }
        }
    })
}

fn MyKeys(cx: Scope) -> Element {
    cx.render(rsx! {
        table {
            class: "mykeys",
            thead {
                tr {
                    th {
                        "Fingerprint"
                    }
                    th {
                        "Name"
                    }
                    th {
                        "Email"
                    }
                    th {
                        "Actions"
                    }
                }
            }
            tbody {
                tr {
                    td {
                        class: "fingerprint",
                        "fp:jf^:GW)T=&^}}dg-$6VVm"
                    }
                    td {
                        class: "name",
                        "Ben Weinstein-Raun"
                    }
                    td {
                        class: "email",
                        "b@w-r.me"
                    }
                    td {
                        class: "actions",
                        button {
                            "Copy Public Key",
                        }
                        button {
                            "Send To New Device"
                        }
                        button {
                            "Delete",
                        }
                    }
                }
            }
        }
        button {
            "Create new keypair"
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
