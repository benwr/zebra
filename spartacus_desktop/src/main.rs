#![allow(non_snake_case)]
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use dioxus::prelude::*;
use dioxus_free_icons::{
    icons::fa_regular_icons::{FaCopy, FaTrashCan},
    Icon,
};

use copypasta::{ClipboardContext, ClipboardProvider};

use printable_ascii::PrintableAsciiString;
use spartacus::about::About;
use spartacus_crypto::{PublicKey, SignedMessage};
use spartacus_storage::{default_db_path, Database};

fn main() {
    #[cfg(not(feature = "debug"))]
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
struct TextToSign(String);
struct MessageToVerify(Option<SignedMessage>);
struct SelectedPrivateSigner(Option<PublicKey>);
struct SelectedPublicSigners(BTreeSet<PublicKey>);

fn App(cx: Scope) -> Element {
    let desktop = dioxus_desktop::use_window(cx);
    desktop.set_title("Spartacus");

    use_shared_state_provider(cx, || ActiveTab::MyKeys);
    use_shared_state_provider(cx, || NewPrivateName(String::new()));
    use_shared_state_provider(cx, || NewPrivateEmail(PrintableAsciiString::default()));
    use_shared_state_provider(cx, || TextToSign(String::new()));
    use_shared_state_provider(cx, || MessageToVerify(None));
    use_shared_state_provider(cx, || SelectedPublicSigners(BTreeSet::new()));

    let db = Database::new(default_db_path());

    use_shared_state_provider(cx, || {
        SelectedPrivateSigner({
            if let Ok(ref d) = db {
                d.visible_contents.my_public_keys.iter().next().cloned()
            } else {
                None
            }
        })
    });

    use_shared_state_provider(cx, || db);

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

#[derive(PartialEq, Props)]
struct DeleteButtonProps {
    k: PublicKey,
    private: bool,
}

fn DeleteButton(cx: Scope<DeleteButtonProps>) -> Element {
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    let selected_private_signer = use_shared_state::<SelectedPrivateSigner>(cx).unwrap();
    let selected_public_signers = use_shared_state::<SelectedPublicSigners>(cx).unwrap();
    cx.render(rsx! {
        a {
            class: "delete_button",
            href: "",
            onclick: {
                move |e| {
                    e.stop_propagation();
                    match dbresult.write().deref_mut() {
                        Ok(ref mut db) => {
                            if cx.props.private {
                                let _ = db.delete_private_key(&cx.props.k);
                                let mut private_signer_write = selected_private_signer.write();
                                let private_signer = private_signer_write.deref_mut();
                                if private_signer.0 == Some(cx.props.k.clone()) {
                                    *private_signer = SelectedPrivateSigner(db.visible_contents.my_public_keys.iter().next().cloned());
                                }
                            } else {
                                let _ = db.delete_public_key(&cx.props.k);
                                let mut public_signer_write = selected_public_signers.write();
                                let public_signer = public_signer_write.deref_mut();
                                public_signer.0.remove(&cx.props.k);
                            }
                        }
                        Err(_e) => {}
                    }
                }
            },
            Icon {
                width: 15,
                height: 15,
                fill: "#cc3333",
                icon: FaTrashCan,
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
    let selected_private_signer = use_shared_state::<SelectedPrivateSigner>(cx).unwrap();
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
                                let mut selected_private_signer_write = selected_private_signer.write();
                                if selected_private_signer_write.deref().0.is_none() {
                                    *selected_private_signer_write = SelectedPrivateSigner(db.visible_contents.my_public_keys.iter().next().cloned());

                                }
                            }
                        }
                    }
                    Err(_e) => {}
                }
            },
            id: new_key_form_id
        }
        div {
            class: "toolbar",
            "Hi there!"
        }
        div {
            class: "data",
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
                    for k in keys.into_iter() {
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
                                a {
                                    href: "",
                                    title: "Copy Public Key",
                                    onclick: {
                                        let k_copy = k.clone();
                                        move |e| {
                                            e.stop_propagation();
                                            if let Ok(mut ctx) = ClipboardContext::new() {
                                                let _ = ctx.set_contents(k_copy.clone().into());
                                            }
                                        }
                                    },
                                    Icon {
                                        width: 15,
                                        height: 15,
                                        fill: "black",
                                        icon: FaCopy,
                                    }
                                }
                            }
                            td {
                                class: "fingerprint",
                                k.fingerprint()
                            }
                            td {
                                class: "delete",
                                DeleteButton {
                                    k: k.clone(),
                                    private: true
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
        }
    })
}

fn OtherKeys(cx: Scope) -> Element {
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    let dbread = dbresult.read();
    let keys = match dbread.deref() {
        Ok(ref db) => db.visible_contents.their_public_keys.clone(),
        Err(ref e) => {
            return cx.render(rsx! {
                "Error reading database: {e}"
            })
        }
    };

    cx.render(rsx! {
        div {
            class: "toolbar",
            "Hi there!"
        },
        div {
            class: "data",
        table {
            class: "otherkeys",
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
                for k in keys.into_iter() {
                    tr {
                        td {
                            class: "name",
                            k.0.holder.name().clone(),
                        }
                        td {
                            class: "email",
                            k.0.holder.email().as_str().to_string(),
                        }
                        td {
                            class: "actions",
                            a {
                                href: "",
                                title: "Copy Public Key",
                                onclick: {
                                    let k_copy = k.clone();
                                    move |e| {
                                        e.stop_propagation();
                                        if let Ok(mut ctx) = ClipboardContext::new() {
                                            let _ = ctx.set_contents(k_copy.0.clone().into());
                                        }
                                    }
                                },
                                Icon {
                                    width: 15,
                                    height: 15,
                                    fill: "black",
                                    icon: FaCopy,
                                }
                            }
                        }
                        td {
                            class: "fingerprint",
                            k.0.fingerprint()
                        }
                        td {
                            class: "delete",
                            DeleteButton {
                                k: k.0.clone(),
                                private: false,
                            }
                        }
                    }
                }
            }
        }
        button {
            onclick: move |_| {
                if let Ok(ref mut db) = dbresult.write().deref_mut() {
                    if let Ok(mut ctx) = ClipboardContext::new() {
                        if let Ok(contents) = ctx.get_contents() {
                            let mut to_import = vec![];
                            for line in contents.split('\n') {
                                if let Ok(key) = PublicKey::from_str(&line) {
                                    to_import.push(key)
                                } else {
                                    return;
                                }
                            }
                            let _ = db.add_public_keys(&to_import);
                        }
                    }
                }
            },
            "Import from Clipboard"
        }
        }
    })
}

fn PrivateSignerSelect(cx: Scope) -> Element {
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    let dbread = dbresult.read();
    let my_keys = match dbread.deref() {
        Ok(ref db) => db
            .visible_contents
            .my_public_keys
            .clone()
            .into_iter()
            .map(|k| (k.fingerprint(), k))
            .collect::<BTreeMap<_, _>>(),
        Err(ref e) => {
            return cx.render(rsx! {
                "Error reading database: {e}"
            })
        }
    };
    let my_keys_clone = my_keys.clone();

    let selected_private_signer = use_shared_state::<SelectedPrivateSigner>(cx).unwrap();
    let k = selected_private_signer.read().deref().0.clone();
    let selected_fingerprint = k.map(|k| k.fingerprint());

    cx.render(rsx! {
        select {
            oninput: move |evt| {
                let mut selected_signer = selected_private_signer.write();
                let selected_private_signer = selected_signer.deref_mut();
                if let Some(k) = my_keys_clone.get(&evt.value) {
                    *selected_private_signer = SelectedPrivateSigner(Some(k.clone()));
                }
            },
            for (fp, k) in my_keys {
                option {
                    value: "{fp}",
                    selected: {
                        selected_fingerprint.as_ref().map(|k| &fp == k).unwrap_or(false)
                    },
                    {
                        format!("{} <{}> {}", k.holder.name(), k.holder.email(), fp)
                    }
                }
            }
        }
    })
}

#[derive(PartialEq, Props)]
struct PublicSignerSelectProps {
    k: PublicKey,
}

fn PublicSignerSelect(cx: Scope<PublicSignerSelectProps>) -> Element {
    let selected_public_signers = use_shared_state::<SelectedPublicSigners>(cx).unwrap();
    let current_signers = selected_public_signers.read();
    cx.render(rsx! {
            input {
                oninput: move |e| {
                    let mut signers = selected_public_signers.write();
                    let signers = signers.deref_mut();
                    if e.value == "true" {
                        signers.0.insert(cx.props.k.clone().clone());
                    } else {
                        signers.0.remove(&cx.props.k);
                    }
                },
                checked: "{current_signers.0.contains(&cx.props.k)}",
                "type": "checkbox",
            }
    })
}

fn Sign(cx: Scope) -> Element {
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    let dbread = dbresult.read();
    let their_keys = match dbread.deref() {
        Ok(ref db) => db.visible_contents.their_public_keys.clone(),
        Err(ref e) => {
            return cx.render(rsx! {
                "Error reading database: {e}"
            })
        }
    };

    let text_to_sign = use_shared_state::<TextToSign>(cx).unwrap();
    let text_to_sign_val = text_to_sign.read().deref().0.clone();

    cx.render(rsx! {
        div {
            class: "toolbar",
            "Hi there!"
        },
        div {
            class: "data",
        b {
            "Text To Sign: "
        }
        br {}
        textarea {
            value: "{text_to_sign_val}",
            oninput: move |evt| *text_to_sign.write() = TextToSign(evt.value.clone()),
            class: "sign_text"
        }
        br {}
        br {}
        b {
            "My Key: "
        }
        PrivateSignerSelect {}
        br {}
        br {}
        b {
            "Other Keys: "
        }
        br {}
        table {
            class: "otherkeys",
            thead {
                tr {
                    th {
                        "Include"
                    }
                    th {
                        "Name"
                    }
                    th {
                        "Email"
                    }
                    th {
                        "Fingerprint"
                    }
                }
            }
            tbody {
                for k in their_keys {
                    tr {
                        td {
                            PublicSignerSelect {
                                k: k.0.clone()
                            }
                        }
                        td {
                            class: "name",
                            k.0.holder.name()
                        }
                        td {
                            class: "email",
                            k.0.holder.email()
                        }
                        td {
                            class: "fingerprint",
                            k.0.fingerprint()
                        }
                    }
                }
            }
        }
        br {}
        SignAndCopy {}
        }
    })
}

fn SignAndCopy(cx: Scope) -> Element {
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    let text_to_sign = use_shared_state::<TextToSign>(cx).unwrap();
    let text_to_sign_val = text_to_sign.read().deref().0.clone();
    let selected_public_signers = use_shared_state::<SelectedPublicSigners>(cx).unwrap();
    let current_signers = selected_public_signers
        .read()
        .0
        .clone()
        .into_iter()
        .collect::<Vec<_>>();
    let selected_private_signer = use_shared_state::<SelectedPrivateSigner>(cx).unwrap();
    let k = selected_private_signer.read().deref().0.clone();
    cx.render(rsx!{
        button {
            onclick: move |_| {
                if let Ok(ref mut db) = dbresult.write().deref_mut() {
                    if let Ok(mut ctx) = ClipboardContext::new() {
                        if let Some(k) = &k {
                            if let Ok(signed_message) = db.sign(&text_to_sign_val, &k, &current_signers) {
                                let _ = ctx.set_contents(String::from(&signed_message));
                            }
                        }
                    }
                }
            },
            "Copy Signed Message to Clipboard"
        }
    })
}

fn PasteAndVerify(cx: Scope) -> Element {
    let message_to_verify = use_shared_state::<MessageToVerify>(cx).unwrap();
    cx.render(rsx! {
        button {
            onclick: move |_| {
                let mut message_to_verify = message_to_verify.write();
                if let Ok(mut ctx) = ClipboardContext::new() {
                    if let Ok(message) = ctx.get_contents() {
                        if let Ok(signed_message) = SignedMessage::from_str(&message) {
                            *message_to_verify = MessageToVerify(Some(signed_message));
                        } else {
                            *message_to_verify = MessageToVerify(None);
                        }
                    } else {
                        *message_to_verify = MessageToVerify(None);
                    }
                } else {
                    *message_to_verify = MessageToVerify(None);
                }
            },
            "Verify Message From Clipboard"
        }
    })
}

#[derive(PartialEq, Props)]
struct VerificationResultsProps {
    signed_message: SignedMessage,
}

fn VerificationResults(cx: Scope<VerificationResultsProps>) -> Element {
    if cx.props.signed_message.verify() {
        cx.render(rsx!{
            b {
                "Message:"
            }
            br {}
            "{cx.props.signed_message.message}"
            br {}
            br {}
            b {
                "This message was signed by someone with the private key associated with one of these identities:"
            }
            table {
                thead {
                    th {
                        "Name"
                    }
                    th {
                        "Email"
                    }
                    th {
                        "Fingerprint"
                    }
                }
                tbody {
                    for (pubkey, _) in cx.props.signed_message.ring.iter() {
                        tr {
                            td {
                                "{pubkey.holder.name()}"
                            }
                            td {
                                "{pubkey.holder.email()}"
                            }
                            td {
                                "{pubkey.fingerprint()}"
                            }
                        }
                    }
                }
            }
        })
    } else {
        cx.render(rsx! {
            b {
                "Message:"
            }
            br {}
            "{cx.props.signed_message.message}"
            br {}
            "Failed to verify."
        })
    }
}

fn Verify(cx: Scope) -> Element {
    let message_to_verify = use_shared_state::<MessageToVerify>(cx).unwrap();
    let message_to_verify_val = message_to_verify.read().deref().0.clone();

    if let Some(signed_message) = message_to_verify_val {
        cx.render(rsx! {
            div {
                class: "toolbar",
                "Hi there!"
            },
            div {
                class: "data",
                div {
                    PasteAndVerify {}
                    br {}
                    br {}
                    VerificationResults {
                        signed_message: signed_message
                    }
                }
            }
        })
    } else {
        cx.render(rsx! {
            div {
                class: "toolbar",
                "Hi there!"
            },
            div {
                class: "data",
                div {
                    PasteAndVerify {}
                }
            }
        })
    }
}
