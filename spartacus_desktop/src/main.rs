#![allow(non_snake_case)]

use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use copypasta::{ClipboardContext, ClipboardProvider};
use dioxus::prelude::*;

use printable_ascii::PrintableAsciiString;
use spartacus::about::About;
use spartacus_storage::{default_db_path, Database};

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

struct NewPrivateName(String);
struct NewPrivateEmail(PrintableAsciiString);
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
    use_shared_state_provider(cx, || NewPrivateName(String::new()));
    use_shared_state_provider(cx, || NewPrivateEmail(PrintableAsciiString::default()));
    use_shared_state_provider(cx, || SignListNameFilter(String::new()));
    use_shared_state_provider(cx, || SignListEmailFilter(String::new()));
    use_shared_state_provider(cx, || SignListFingerprintFilter(String::new()));
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
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    let dbread = dbresult.read();
    let new_private_name = use_shared_state::<NewPrivateName>(cx).unwrap();
    let new_private_name_val = new_private_name.read().deref().0.clone();
    let new_private_name_copy = new_private_name.read().deref().0.clone();
    let new_private_email = use_shared_state::<NewPrivateEmail>(cx).unwrap();
    let new_private_email_val = new_private_email.read().deref().0.clone();
    let new_private_email_copy = new_private_email.read().deref().0.clone();
    let keys = match dbread.deref() {
        Ok(ref db) => db.visible_contents.my_public_keys.clone(),
        Err(ref e) => {
            return cx.render(rsx! {
                "Error reading database: {e}"
            })
        }
    };

    let new_key_form_id = "new_key_form";

    cx.render(rsx! {
        form {
            onsubmit: move |_| {
                match dbresult.write().deref_mut() {
                    Ok(ref mut db) => {
                        if let Ok(email) = PrintableAsciiString::from_str(&new_private_email_copy) {
                            if let Ok(()) = db.new_private_key(&new_private_name_copy, &email) {
                                *new_private_name.write() = NewPrivateName("".to_string());
                                *new_private_email.write() = NewPrivateEmail(PrintableAsciiString::default());
                            }
                        }
                    }
                    Err(_e) => {}
                }
            },
            id: new_key_form_id
        }
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
                        "Actions"
                    }
                    th {
                        "Fingerprint"
                    }
                    th {
                        "Delete"
                    }
                }
            }
            tbody {
                for (i, k) in keys.into_iter().enumerate() {
                    tr {
                        td {
                            class: "name",
                            k.holder.name().clone(),
                        }
                        td {
                            class: "email",
                            k.holder.email().as_str().to_string(),
                        }
                        td {
                            class: "actions",
                            button {
                                onclick: move |_| {
                                    if let Ok(mut ctx) = ClipboardContext::new() {
                                        let _ = ctx.set_contents(k.clone().into());
                                    }
                                },
                                "Copy public key"
                            }
                        }
                        td {
                            class: "fingerprint",
                            k.fingerprint()
                        }
                        td {
                            class: "delete",
                            button {
                                onclick: move |_| {
                                    match dbresult.write().deref_mut() {
                                        Ok(ref mut db) => {
                                            let _ = db.delete_private_key(i);
                                        }
                                        Err(_e) => {}
                                    }
                                },
                                "X",
                            }
                        }
                    }
                }
                tr {
                    td {
                        class: "name",
                        input {
                            class: "new_key_name_input",
                            value: "{new_private_name_val}",
                            form: new_key_form_id,
                            oninput: move |evt| *new_private_name.write() = NewPrivateName(evt.value.clone())
                        }
                    }
                    td {
                        class: "email",
                        input {
                            class: "new_key_email_input",
                            value: "{new_private_email_val}",
                            form: new_key_form_id,
                            oninput: move |evt| {
                                if let Ok(new) = PrintableAsciiString::from_str(&evt.value) {
                                    *new_private_email.write() = NewPrivateEmail(new)
                                } else {
                                    *new_private_email.write() = NewPrivateEmail(new_private_email_val.clone())
                                }
                            }
                        }
                    }
                    td {
                        class: "actions",
                        input {
                            "type": "submit",
                            form: new_key_form_id,
                            value: "Create New Keypair"
                        }
                    }
                    td {
                        class: "fingerprint",
                    }
                }
            }
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
