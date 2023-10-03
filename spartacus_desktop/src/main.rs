#![allow(non_snake_case)]
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use dioxus::prelude::*;
use dioxus_desktop::{
    tao::menu::{MenuBar, MenuItem},
    WindowBuilder,
};
use dioxus_free_icons::{
    icons::go_icons::{GoCopy, GoPlusCircle, GoSearch, GoShieldCheck, GoShieldLock, GoTrash, GoUnverified, GoVerified},
    Icon,
};

use copypasta::{ClipboardContext, ClipboardProvider};

use printable_ascii::PrintableAsciiString;
use spartacus::about::About;
use spartacus_crypto::{PublicKey, SignedMessage};
use spartacus_storage::{default_db_path, Database, VerificationInfo};

fn make_config() -> dioxus_desktop::Config {
    let mut main_menu = MenuBar::new();
    let mut edit_menu = MenuBar::new();
    let mut window_menu = MenuBar::new();
    let mut application_menu = MenuBar::new();

    application_menu.add_native_item(MenuItem::Quit);

    edit_menu.add_native_item(MenuItem::Undo);
    edit_menu.add_native_item(MenuItem::Redo);
    edit_menu.add_native_item(MenuItem::Separator);
    edit_menu.add_native_item(MenuItem::Cut);
    edit_menu.add_native_item(MenuItem::Copy);
    edit_menu.add_native_item(MenuItem::Paste);
    edit_menu.add_native_item(MenuItem::SelectAll);

    window_menu.add_native_item(MenuItem::Minimize);
    window_menu.add_native_item(MenuItem::Zoom);
    window_menu.add_native_item(MenuItem::Separator);
    window_menu.add_native_item(MenuItem::ShowAll);
    window_menu.add_native_item(MenuItem::EnterFullScreen);

    main_menu.add_submenu("Spartacus", true, application_menu);
    main_menu.add_submenu("Edit", true, edit_menu);
    main_menu.add_submenu("Window", true, window_menu);

    dioxus_desktop::Config::default().with_window(
        WindowBuilder::new()
            .with_title("Spartacus")
            .with_min_inner_size(dioxus_desktop::tao::dpi::Size::Logical(
                dioxus_desktop::tao::dpi::LogicalSize {
                    width: 900.0,
                    height: 600.0,
                },
            ))
            .with_menu(main_menu),
    )
}

fn main() {
    #[cfg(not(feature = "debug"))]
    // This is overkill, but also cheap.
    if let Err(e) = secmem_proc::harden_process() {
        eprintln!("Error: Could not harden process; exiting. {e}");
        return;
    }
    dioxus_desktop::launch_cfg(App, make_config());
}

#[derive(Clone, Copy, Debug)]
enum ActiveTab {
    MyKeys,
    OtherKeys,
    Sign,
    Verify,
    About,
    Danger,
}

struct NewPrivateName(String);
struct NewPrivateEmail(PrintableAsciiString);
struct TextToSign(String);
struct MessageToVerify(Option<SignedMessage>);
struct SelectedPrivateSigner(Option<PublicKey>);
struct SelectedPublicSigners(BTreeSet<PublicKey>);

#[derive(Clone)]
struct TableFilter {
    name: String,
    email: String,
    fingerprint: String,
}

struct PrivateFilter(TableFilter);
struct PublicFilter(TableFilter);
struct SignerFilter(TableFilter);
struct DangerFilter(TableFilter);

trait Filter {
    fn set_name(&mut self, name: &str);
    fn set_email(&mut self, email: &str);
    fn set_fingerprint(&mut self, fingerprint: &str);
}

impl Filter for PrivateFilter {
    fn set_name(&mut self, name: &str) {
        self.0.name = name.to_string();
    }

    fn set_email(&mut self, email: &str) {
        self.0.email = email.to_string();
    }

    fn set_fingerprint(&mut self, fingerprint: &str) {
        self.0.fingerprint = fingerprint.to_string();
    }
}

impl Filter for PublicFilter {
    fn set_name(&mut self, name: &str) {
        self.0.name = name.to_string();
    }

    fn set_email(&mut self, email: &str) {
        self.0.email = email.to_string();
    }

    fn set_fingerprint(&mut self, fingerprint: &str) {
        self.0.fingerprint = fingerprint.to_string();
    }
}

impl Filter for SignerFilter {
    fn set_name(&mut self, name: &str) {
        self.0.name = name.to_string();
    }

    fn set_email(&mut self, email: &str) {
        self.0.email = email.to_string();
    }

    fn set_fingerprint(&mut self, fingerprint: &str) {
        self.0.fingerprint = fingerprint.to_string();
    }
}

impl Filter for DangerFilter {
    fn set_name(&mut self, name: &str) {
        self.0.name = name.to_string();
    }

    fn set_email(&mut self, email: &str) {
        self.0.email = email.to_string();
    }

    fn set_fingerprint(&mut self, fingerprint: &str) {
        self.0.fingerprint = fingerprint.to_string();
    }
}

fn App(cx: Scope) -> Element {
    let desktop = dioxus_desktop::use_window(cx);
    desktop.set_title("Spartacus");

    use_shared_state_provider(cx, || ActiveTab::MyKeys);
    use_shared_state_provider(cx, || NewPrivateName(String::new()));
    use_shared_state_provider(cx, || NewPrivateEmail(PrintableAsciiString::default()));
    use_shared_state_provider(cx, || TextToSign(String::new()));
    use_shared_state_provider(cx, || MessageToVerify(None));
    use_shared_state_provider(cx, || SelectedPublicSigners(BTreeSet::new()));
    use_shared_state_provider(cx, || {
        SignerFilter(TableFilter {
            name: String::new(),
            email: String::new(),
            fingerprint: String::new(),
        })
    });
    use_shared_state_provider(cx, || {
        PrivateFilter(TableFilter {
            name: String::new(),
            email: String::new(),
            fingerprint: String::new(),
        })
    });
    use_shared_state_provider(cx, || {
        PublicFilter(TableFilter {
            name: String::new(),
            email: String::new(),
            fingerprint: String::new(),
        })
    });
    use_shared_state_provider(cx, || {
        DangerFilter(TableFilter {
            name: String::new(),
            email: String::new(),
            fingerprint: String::new(),
        })
    });

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
        div {
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
                        ActiveTab::Danger => rsx! { Danger {} },
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
            div {
                onclick: move |_| {*use_shared_state::<ActiveTab>(cx).unwrap().write() = ActiveTab::Danger},
                class: {
                    if let ActiveTab::Danger = active_tab {
                        "tab_choice danger_tab active_tab"
                    } else {
                        "tab_choice danger_tab inactive_tab"
                    }
                },
                "Danger"
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
            class: "delete_button action_button",
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
                icon: GoTrash,
            }
        }
    })
}

#[derive(PartialEq, Props)]
struct VerifyButtonProps {
    k: PublicKey,
    verif: VerificationInfo,
}

fn VerifyButton(cx: Scope<VerifyButtonProps>) -> Element {
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    if let Some(t) = cx.props.verif.verified_time() {
        cx.render(rsx! {
            a {
                class: "action_button",
                href: "",
                title: "Verified {t.date()}",
                onclick: {
                    move |e| {
                        e.stop_propagation();
                        match dbresult.write().deref_mut() {
                            Ok(ref mut db) => {
                                let _ = db.set_unverified(&cx.props.k);
                            }
                            Err(_e) => {}
                        }
                    }
                },
                Icon {
                    width: 15,
                    height: 15,
                    fill: "#00f",
                    icon: GoVerified,
                }
            }
        })
    } else {
        cx.render(rsx! {
            a {
                class: "action_button",
                href: "",
                title: "This key is unverified",
                onclick: {
                    move |e| {
                        e.stop_propagation();
                        match dbresult.write().deref_mut() {
                            Ok(ref mut db) => {
                                let _ = db.set_verified(&cx.props.k);
                            }
                            Err(_e) => {}
                        }
                    }
                },
                Icon {
                    width: 15,
                    height: 15,
                    fill: "#999",
                    icon: GoUnverified,
                }
            }
        })
    }
}

fn FilterRow<T: Filter + 'static>(cx: Scope) -> Element {
    let filter = use_shared_state::<T>(cx).unwrap();

    cx.render(rsx! {
        tr {
            class: "filter_row",
            td {
                class: "name",
                input {
                    "type": "text",
                    placeholder: "Filter names",
                    oninput: move |evt| filter.write().set_name(&evt.value)
                }
                Icon {
                    class: "search_icon",
                    width: 16,
                    height: 16,
                    fill: "black",
                    icon: GoSearch,
                }
            }
            td {
                class: "email",
                input {
                    "type": "text",
                    placeholder: "Filter emails",
                    oninput: move |evt| filter.write().set_email(&evt.value)
                }
                Icon {
                    class: "search_icon",
                    width: 16,
                    height: 16,
                    fill: "black",
                    icon: GoSearch,
                }
            }
            td {
                class: "fingerprint",
                input {
                    "type": "text",
                    placeholder: "Filter fingerprints",
                    oninput: move |evt| filter.write().set_fingerprint(&evt.value)
                }
                Icon {
                    class: "search_icon",
                    width: 16,
                    height: 16,
                    fill: "black",
                    icon: GoSearch,
                }
            }
            td {
                class: "delete"
            }
        }
    })
}

fn Danger(cx: Scope) -> Element {
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    let dbread = dbresult.read();
    let keys = match dbread.deref() {
        Ok(ref db) => db.visible_contents.my_public_keys.clone(),
        Err(ref e) => {
            return cx.render(rsx! {
                "Error reading database: {e}"
            })
        }
    };
    let filter = use_shared_state::<DangerFilter>(cx).unwrap();

    let filter_name = filter.read().0.name.to_lowercase();
    let filter_email = filter.read().0.email.to_lowercase();
    let filter_fingerprint = filter.read().0.fingerprint.replace(' ', "").to_lowercase();

    cx.render(rsx! {
        div {
            class: "toolbar",
            "WARNING: The actions on this tab are irreversible!"
        }
        div {
            class: "data",
            table {
                class: "mykeys",
                thead {
                    FilterRow::<DangerFilter> {}
                }
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
                    for k in keys.into_iter() {
                        if k.holder().name().to_lowercase().contains(&filter_name)
                            && k.holder().email().to_lowercase().contains(&filter_email)
                            && k.fingerprint().replace(' ', "").to_lowercase().contains(&filter_fingerprint)
                        {
                            rsx!{
                                tr {
                                    key: "{k.fingerprint()}",
                                    td {
                                        class: "name",
                                        k.holder().name().clone(),
                                    }
                                    td {
                                        class: "email",
                                        k.holder().email().as_str().to_string(),
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
                        }
                    }
                }
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

    let filter = use_shared_state::<PrivateFilter>(cx).unwrap();

    let filter_name = filter.read().0.name.to_lowercase();
    let filter_email = filter.read().0.email.to_lowercase();
    let filter_fingerprint = filter.read().0.fingerprint.replace(' ', "").to_lowercase();

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
            Icon {
                class: "action_icon",
                width: 15,
                height: 15,
                fill: "black",
                icon: GoPlusCircle,
            }
            input {
                class: "new_key_name_input",
                value: "{new_private_name_val}",
                placeholder: "New Key Name",
                form: new_key_form_id,
                oninput: move |evt| *new_private_name.write() = NewPrivateName(evt.value.clone())
            }
            input {
                class: "new_key_email_input",
                value: "{new_private_email_val}",
                placeholder: "New Key Email",
                form: new_key_form_id,
                oninput: move |evt| {
                    if let Ok(new) = PrintableAsciiString::from_str(&evt.value) {
                        *new_private_email.write() = NewPrivateEmail(new)
                    } else {
                        *new_private_email.write() = NewPrivateEmail(new_private_email_val.clone())
                    }
                }
            }
            input {
                "type": "submit",
                form: new_key_form_id,
                value: "Create New Keypair",
            }
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
                            "Fingerprint"
                        }
                        th {
                            "Actions"
                        }
                    }
                }
                tbody {
                    FilterRow::<PrivateFilter> {}
                    for k in keys.into_iter() {
                        if k.holder().name().to_lowercase().contains(&filter_name)
                            && k.holder().email().to_lowercase().contains(&filter_email)
                            && k.fingerprint().replace(' ', "").to_lowercase().contains(&filter_fingerprint)
                        {
                            rsx! {
                                tr {
                                    key: "{k.fingerprint()}",
                                    td {
                                        class: "name",
                                        k.holder().name().clone(),
                                    }
                                    td {
                                        class: "email",
                                        k.holder().email().as_str().to_string(),
                                    }
                                    td {
                                        class: "fingerprint",
                                        k.fingerprint()
                                    }
                                    td {
                                        class: "actions",
                                        a {
                                            href: "",
                                            title: "Copy Public Key",
                                            class: "action_button",
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
                                                icon: GoCopy,
                                            }
                                        }
                                    }
                                }
                            }
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

    let filter = use_shared_state::<PublicFilter>(cx).unwrap();

    let filter_name = filter.read().0.name.to_lowercase();
    let filter_email = filter.read().0.email.to_lowercase();
    let filter_fingerprint = filter.read().0.fingerprint.replace(' ', "").to_lowercase();

    cx.render(rsx! {
        div {
            class: "toolbar",
            Icon {
                class: "action_icon",
                width: 15,
                height: 15,
                fill: "black",
                icon: GoPlusCircle,
            }
            button {
                onclick: move |_| {
                    if let Ok(ref mut db) = dbresult.write().deref_mut() {
                        if let Ok(mut ctx) = ClipboardContext::new() {
                            if let Ok(contents) = ctx.get_contents() {
                                let mut to_import = vec![];
                                for line in contents.split('\n') {
                                    if let Ok(key) = PublicKey::from_str(line) {
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
                "Import Public Key from Clipboard"
            }
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
                            "Fingerprint"
                        }
                        th {
                            "Actions"
                        }
                    }
                }
                tbody {
                    FilterRow::<PublicFilter> {}
                    for k in keys.into_iter() {
                        if k.0.holder().name().to_lowercase().contains(&filter_name)
                            && k.0.holder().email().to_lowercase().contains(&filter_email)
                            && k.0.fingerprint().replace(' ', "").to_lowercase().contains(&filter_fingerprint)
                        {
                            rsx! {
                                tr {
                                    key: "{k.0.fingerprint()}",
                                    td {
                                        class: "name",
                                        k.0.holder().name().clone(),
                                    }
                                    td {
                                        class: "email",
                                        k.0.holder().email().as_str().to_string(),
                                    }
                                    td {
                                        class: "fingerprint",
                                        k.0.fingerprint()
                                    }
                                    td {
                                        class: "actions",
                                        VerifyButton {
                                            k: k.0.clone(),
                                            verif: k.1.clone(),
                                        }
                                        a {
                                            href: "",
                                            title: "Copy Public Key",
                                            class: "action_button",
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
                                                icon: GoCopy,
                                            }
                                        },
                                        DeleteButton {
                                            k: k.0.clone(),
                                            private: false,
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
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
                        format!("{} <{}> {}", k.holder().name(), k.holder().email(), fp)
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

    let filter = use_shared_state::<SignerFilter>(cx).unwrap();

    let filter_name = filter.read().0.name.to_lowercase();
    let filter_email = filter.read().0.email.to_lowercase();
    let filter_fingerprint = filter.read().0.fingerprint.replace(' ', "").to_lowercase();

    cx.render(rsx! {
        div {
            class: "toolbar",
            Icon {
                class: "action_icon",
                width: 15,
                height: 15,
                fill: "black",
                icon: GoShieldLock,
            }
            SignAndCopy {}
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
                        "Name"
                    }
                    th {
                        "Email"
                    }
                    th {
                        "Fingerprint"
                    }
                    th {
                        "Verified?"
                    }
                    th {
                        "Include"
                    }
                }
            }
            tbody {
                FilterRow::<SignerFilter> {}
                for k in their_keys.into_iter() {
                    if k.0.holder().name().to_lowercase().contains(&filter_name)
                        && k.0.holder().email().to_lowercase().contains(&filter_email)
                        && k.0.fingerprint().replace(' ', "").to_lowercase().contains(&filter_fingerprint)
                    {
                        rsx! {
                            tr {
                                key: "{k.0.fingerprint()}",
                                td {
                                    class: "name",
                                    k.0.holder().name()
                                }
                                td {
                                    class: "email",
                                    k.0.holder().email()
                                }
                                td {
                                    class: "fingerprint",
                                    k.0.fingerprint()
                                }
                                td {
                                    class: "actions",
                                    if let Some(t) = k.1.verified_time() {
                                        rsx! {
                                            span {
                                                title: "Verified {t.date()}",
                                                Icon {
                                                    width: 15,
                                                    height: 15,
                                                    fill: "#00f",
                                                    icon: GoVerified,
                                                }
                                            }
                                        }
                                    }
                                }
                                td {
                                    class: "actions",
                                    PublicSignerSelect {
                                        k: k.0.clone()
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
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
                            if let Ok(signed_message) = db.sign(&text_to_sign_val, k, &current_signers) {
                                let _ = ctx.set_contents(String::from(&signed_message));
                            }
                        }
                    }
                }
            },
            "Sign and Copy to Clipboard"
        }
    })
}

fn PasteAndVerify(cx: Scope) -> Element {
    let message_to_verify = use_shared_state::<MessageToVerify>(cx).unwrap();
    cx.render(rsx! {
        button {
            onclick: move |_| {
                let mut message_to_verify = message_to_verify.write();
                if let Some(message) = ClipboardContext::new()
                    .and_then(|mut ctx| ctx.get_contents())
                        .ok()
                        .and_then(|m| SignedMessage::from_str(&m).ok())
                {
                    *message_to_verify = MessageToVerify(Some(message));
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
    let dbresult = use_shared_state::<std::io::Result<Database>>(cx).unwrap();
    let (known_keys, my_keys) = match *dbresult.read() {
        Ok(ref db) => (
            db.visible_contents.their_public_keys.clone(),
            db.visible_contents.my_public_keys.clone(),
        ),
        Err(_) => (BTreeMap::new(), BTreeSet::new()),
    };

    let mut all_known = true;
    let mut all_verified = true;
    for pubkey in cx.props.signed_message.ring() {
        if !my_keys.contains(pubkey) {
            match known_keys.get(pubkey) {
                None => {
                    all_known = false;
                    all_verified = false;
                }
                Some(v_info) => {
                    if !v_info.is_verified() {
                        all_verified = false;
                    }
                }
            }
        }
    }

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
                if all_known && all_verified {
                    "This message was signed by someone with the private key associated with one of these verified identities:"
                } else if all_known {
                    "This message was signed by someone with the private key associated with one of these identities (all known, but not all verified):"
                } else {
                    "This message was signed by someone with the private key associated with one of these identities, but not all of these are known identities"
                }
            }
            br {}
            br {}
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
                    th {
                        "Known"
                    }
                }
                tbody {
                    for pubkey in cx.props.signed_message.ring() {
                        tr {
                            key: "{pubkey.fingerprint()}",
                            td {
                                class: "name",
                                "{pubkey.holder().name()}"
                            }
                            td {
                                class: "email",
                                "{pubkey.holder().email()}"
                            }
                            td {
                                class: "fingerprint",
                                "{pubkey.fingerprint()}"
                            }
                            td {
                                class: "actions",
                                if my_keys.contains(pubkey) || known_keys.get(pubkey).map(|v| v.is_verified()).unwrap_or(false) {
                                    rsx!{
                                        span {
                                            title: "Key is verified",
                                            Icon {
                                                width: 15,
                                                height: 15,
                                                fill: "#00f",
                                                icon: GoVerified,
                                            }
                                        }
                                    }
                                } else if my_keys.contains(pubkey) || known_keys.contains_key(pubkey) {
                                    rsx!{
                                        span {
                                            title: "Key is known but unverified",
                                            Icon {
                                                width: 15,
                                                height: 15,
                                                fill: "#d80",
                                                icon: GoVerified,
                                            }
                                        }
                                    }
                                }
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
                Icon {
                    class: "action_icon",
                    width: 15,
                    height: 15,
                    fill: "black",
                    icon: GoShieldCheck,
                }
                PasteAndVerify {}
            },
            div {
                class: "data",
                div {
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
                Icon {
                    class: "action_icon",
                    width: 15,
                    height: 15,
                    fill: "black",
                    icon: GoShieldCheck,
                }
                PasteAndVerify {}
            },
            div {
                class: "data",
            }
        })
    }
}
