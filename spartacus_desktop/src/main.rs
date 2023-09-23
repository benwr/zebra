#![allow(non_snake_case)]

use dioxus::prelude::*;

use spartacus::about::About;
use spartacus_storage::{Database, default_db_path};

fn main() {
    // This is overkill, but also cheap.
    if let Err(e) = secmem_proc::harden_process() {
        eprintln!("Error: Could not harden process; exiting. {e}");
        return;
    }
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

struct SignText(String);
struct VerifyText(String);
struct PrivateNameFilter(String);
struct PrivateEmailFilter(String);
struct PrivateFingerprintFilter(String);
struct NewPrivateName(String);
struct NewPrivateEmail(String);
struct AcceptPrivatePassphrase(String);
struct PublicNameFilter(String);
struct PublicEmailFilter(String);
struct PublicFingerprintFilter(String);
struct SignListNameFilter(String);
struct SignListEmailFilter(String);
struct SignListFingerprintFilter(String);

fn App(cx: Scope) -> Element {
    use dioxus_desktop::tao::dpi::{LogicalSize, Size};
    let desktop = dioxus_desktop::use_window(cx);
    desktop.set_title("Spartacus");
    desktop.set_min_inner_size(Some(Size::Logical(LogicalSize {
        width: 640.0,
        height: 256.0,
    })));

    use_shared_state_provider(cx, || ActiveTab::MyKeys);
    use_shared_state_provider(cx, || PrivateNameFilter(String::new()));
    use_shared_state_provider(cx, || PrivateEmailFilter(String::new()));
    use_shared_state_provider(cx, || PrivateFingerprintFilter(String::new()));
    use_shared_state_provider(cx, || NewPrivateName(String::new()));
    use_shared_state_provider(cx, || NewPrivateEmail(String::new()));
    use_shared_state_provider(cx, || AcceptPrivatePassphrase(String::new()));
    use_shared_state_provider(cx, || PublicNameFilter(String::new()));
    use_shared_state_provider(cx, || PublicEmailFilter(String::new()));
    use_shared_state_provider(cx, || PublicFingerprintFilter(String::new()));
    use_shared_state_provider(cx, || SignText(String::new()));
    use_shared_state_provider(cx, || SignListNameFilter(String::new()));
    use_shared_state_provider(cx, || SignListEmailFilter(String::new()));
    use_shared_state_provider(cx, || SignListFingerprintFilter(String::new()));
    use_shared_state_provider(cx, || VerifyText(String::new()));
    use_shared_state_provider(cx, || Database::new(default_db_path()));

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
    use std::ops::Deref;
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap().read();
    let keys = match dbresult.deref() {
        Ok(ref db) => {
            db.visible_contents.my_public_keys.clone()
        }
        Err(ref e) => {
            return cx.render(rsx! {
                "Error reading database: {e}"
            })
        }
    };
    cx.render(rsx! {
        table {
            class: "mykeys",
            thead {
                tr {
                    th {
                        "Name"
                    }
                    th {
                        "Email"
                    }
                    th {
                        "Fingerprint"
                    }
                    th {
                        "Actions"
                    }
                }
            }
            tbody {
                for k in keys {
                    tr {
                        td {
                            class: "name",
                            k.holder.name.clone(),
                        }
                        td {
                            class: "email",
                            k.holder.email.as_str().to_string(),
                        }
                        td {
                            class: "fingerprint",
                            k.fingerprint()
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
                tr {
                    td {
                        class: "name",
                        input {
                            class: "new_key_name_input",
                        }
                    }
                    td {
                        class: "email",
                        input {
                            class: "new_key_email_input",
                        }
                    }
                    td {
                        class: "fingerprint",
                    }
                    td {
                        class: "actions",
                        button {
                            "Create New Keypair"
                        }
                    }
                }
            }
        }
        button {
            "Receive Keypair From Other Device"
        }
    })   
}

fn OtherKeys(cx: Scope) -> Element {
    cx.render(rsx! {
        table {
            class: "otherkeys",
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
                        "Verified"
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
                        "48GRzYT9kxSN8cfM39^#"
                    }
                    td {
                        class: "name",
                        "Kurt Brown"
                    }
                    td {
                        class: "email",
                        "kurt.brown126@gmail.com"
                    }
                    td {
                        class: "verified",
                        input {
                            "type": "date",
                        }
                    }
                    td {
                        class: "actions",
                        button {
                            "Copy Public Key",
                        }
                        button {
                            "Delete",
                        }
                        button {
                            "Verify By Email"
                        }
                    }
                }
                tr {
                    td {
                        class: "fingerprint",
                        "Du&hpGhD@Ld6AVATQNSp"
                    }
                    td {
                        class: "name",
                        "Sam Bankman-Fried"
                    }
                    td {
                        class: "email",
                        "sbf@ftx.us"
                    }
                    td {
                        class: "verified",
                        input {
                            "type": "date",
                        }
                    }
                    td {
                        class: "actions",
                        button {
                            "Copy Public Key",
                        }
                        button {
                            "Delete",
                        }
                        button {
                            "Verify By Email"
                        }
                    }
                }
            }
        }
        button {
            "Add Public Key"
        }
        button {
            "Import Key List"
        }
        button {
            "Delete Selected"
        }
        button {
            "Export Selected"
        }
    })
}

fn Sign(cx: Scope) -> Element {
    cx.render(rsx! {
        "Text To Sign: "
        textarea {}
        br {}
        "My Key: "
        select {
            option {
                "Ben Weinstein-Raun <b@w-r.me> (\"jf^:GW)T=&^}}dg-$6VVm\")"
            }
        }
        br {}
        "Other Keys: "
        table {
            class: "otherkeys",
            thead {
                tr {
                    th {
                        "Include"
                    }
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
                        "Verified"
                    }
                }
            }
            tbody {
                tr {
                    td {
                        input {
                            "type": "checkbox",
                        }
                    }
                    td {
                        class: "fingerprint",
                        "48GRzYT9kxSN8cfM39^#"
                    }
                    td {
                        class: "name",
                        "Kurt Brown"
                    }
                    td {
                        class: "email",
                        "kurt.brown126@gmail.com"
                    }
                    td {
                        class: "verified",
                        input {
                            "type": "date",
                        }
                    }
                }
                tr {
                    td {
                        input {
                            "type": "checkbox",
                        }
                    }
                    td {
                        class: "fingerprint",
                        "Du&hpGhD@Ld6AVATQNSp"
                    }
                    td {
                        class: "name",
                        "Sam Bankman-Fried"
                    }
                    td {
                        class: "email",
                        "sbf@ftx.us"
                    }
                    td {
                        class: "verified",
                        input {
                            "type": "date",
                        }
                    }
                }
            }
        }
        br {}
        button { "Copy Signature" }
    })
}

fn Verify(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
        }
    })
}
