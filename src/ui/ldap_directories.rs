//! LDAP directory settings, separate from mail accounts. Passwords never enter ldap.toml.
use crate::i18n::i18n;
use crate::ldap::{self, Directory};
use adw::prelude::*;

fn error(label: &gtk::Label, message: &str) {
    label.set_text(message);
    label.set_visible(true);
}

fn refresh(list: &gtk::ListBox, status: &gtk::Label, parent: &gtk::Widget) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    let dirs = match ldap::load_directories() {
        Ok(dirs) => {
            status.set_visible(false);
            dirs
        }
        Err(e) => {
            error(
                status,
                &format!("{}: {e}", i18n("Could not read LDAP configuration")),
            );
            return;
        }
    };
    for (index, dir) in dirs.into_iter().enumerate() {
        let row = adw::ActionRow::new();
        row.set_title(&dir.url);
        row.set_subtitle(&dir.base_dn);
        let button = gtk::Button::from_icon_name("document-edit-symbolic");
        button.set_tooltip_text(Some(&i18n("Edit directory")));
        button.set_valign(gtk::Align::Center);
        button.add_css_class("flat");
        row.add_suffix(&button);
        row.set_activatable_widget(Some(&button));
        let parent = parent.clone();
        let list_for_edit = list.clone();
        let status = status.clone();
        button.connect_clicked(move |_| edit_directory(&parent, &list_for_edit, &status, Some(index)));
        list.append(&row);
    }
}

fn edit_directory(
    parent: &gtk::Widget,
    list: &gtk::ListBox,
    status: &gtk::Label,
    index: Option<usize>,
) {
    let dirs = match ldap::load_directories() {
        Ok(dirs) => dirs,
        Err(e) => {
            error(
                status,
                &format!("{}: {e}", i18n("Could not read LDAP configuration")),
            );
            return;
        }
    };
    let existing = index.and_then(|i| dirs.get(i)).cloned();
    let window = adw::Window::new();
    window.set_title(Some(&i18n("LDAP Directory")));
    window.set_default_size(480, 460);
    window.set_modal(true);
    if let Some(root) = parent.root().and_then(|r| r.downcast::<gtk::Window>().ok()) {
        window.set_transient_for(Some(&root));
    }
    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    let save = gtk::Button::with_label(&i18n("Save"));
    save.add_css_class("suggested-action");
    header.pack_end(&save);
    toolbar.add_top_bar(&header);
    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::new();
    group.set_description(Some(&i18n(
        "Use ldaps:// or ldap:// with StartTLS. Searches only read names and email addresses.",
    )));
    let url = adw::EntryRow::new();
    url.set_title(&i18n("Server URL"));
    url.set_text(existing.as_ref().map_or("", |d| &d.url));
    group.add(&url);
    let base = adw::EntryRow::new();
    base.set_title(&i18n("Base DN"));
    base.set_text(existing.as_ref().map_or("", |d| &d.base_dn));
    group.add(&base);
    let bind = adw::EntryRow::new();
    bind.set_title(&i18n("Bind DN (optional)"));
    bind.set_text(existing.as_ref().map_or("", |d| &d.bind_dn));
    group.add(&bind);
    let key = adw::EntryRow::new();
    key.set_title(&i18n("Password key (for bind)"));
    key.set_text(existing.as_ref().map_or("", |d| &d.password_key));
    group.add(&key);
    let password = adw::PasswordEntryRow::new();
    password.set_title(&i18n("Password (leave blank to keep existing)"));
    group.add(&password);
    let message = gtk::Label::new(None);
    message.set_wrap(true);
    message.add_css_class("error");
    message.set_visible(false);
    group.add(&message);
    page.add(&group);
    if let Some(index) = index {
        let remove = gtk::Button::with_label(&i18n("Remove directory"));
        remove.add_css_class("destructive-action");
        let remove_group = adw::PreferencesGroup::new();
        remove_group.add(&remove);
        page.add(&remove_group);
        let window = window.clone();
        let list = list.clone();
        let status = status.clone();
        let parent = parent.clone();
        let message = message.clone();
        remove.connect_clicked(move |_| {
            let Ok(mut dirs) = ldap::load_directories() else {
                error(&message, &i18n("Could not read LDAP configuration"));
                return;
            };
            if index >= dirs.len() {
                return;
            }
            let removed = dirs.remove(index);
            match ldap::save_directories(&dirs) {
                Ok(()) => {
                    if !removed.password_key.is_empty()
                        && !dirs.iter().any(|d| d.password_key == removed.password_key)
                    {
                        crate::config::delete_cloud_password(&format!(
                            "ldap:{}",
                            removed.password_key
                        ));
                    }
                    refresh(&list, &status, &parent);
                    window.close();
                }
                Err(e) => error(&message, &e),
            }
        });
    }
    toolbar.set_content(Some(&page));
    window.set_content(Some(&toolbar));
    let win = window.clone();
    let list = list.clone();
    let status = status.clone();
    let parent = parent.clone();
    save.connect_clicked(move |_| {
        let url_text = url.text().trim().to_string();
        let base_text = base.text().trim().to_string();
        let bind_text = bind.text().trim().to_string();
        let key_text = key.text().trim().to_string();
        if !(url_text.starts_with("ldaps://") || url_text.starts_with("ldap://"))
            || base_text.is_empty()
            || url_text.contains(char::is_whitespace)
            || key_text.contains(['\r', '\n', ':'])
            || (!bind_text.is_empty() && key_text.is_empty())
        {
            error(
                &message,
                &i18n("Enter a valid LDAP URL, base DN and (for a bind) password key."),
            );
            return;
        }
        let Ok(mut dirs) = ldap::load_directories() else {
            error(&message, &i18n("Could not read LDAP configuration"));
            return;
        };
        if dirs
            .iter()
            .enumerate()
            .any(|(i, d)| Some(i) != index && !key_text.is_empty() && d.password_key == key_text)
        {
            error(
                &message,
                &i18n("This password key is already used by another directory."),
            );
            return;
        }
        let old = index.and_then(|i| dirs.get(i)).cloned();
        let secret = password.text().to_string();
        if !bind_text.is_empty()
            && secret.is_empty()
            && (old.as_ref().is_none_or(|d| d.password_key != key_text)
                || crate::config::load_cloud_password(&format!("ldap:{key_text}")).is_none())
        {
            error(&message, &i18n("Enter a password for this bind."));
            return;
        }
        let dir = Directory {
            url: url_text,
            base_dn: base_text,
            bind_dn: bind_text,
            password_key: key_text,
        };
        if let Some(i) = index {
            if i >= dirs.len() {
                error(&message, &i18n("Directory no longer exists."));
                return;
            }
            dirs[i] = dir.clone();
        } else {
            dirs.push(dir.clone());
        }
        // Save the configuration before changing secrets so a failed config write
        // never deletes the old credential. An unsuccessful keyring write is shown.
        if let Err(e) = ldap::save_directories(&dirs) {
            error(&message, &e);
            return;
        }
        if !dir.bind_dn.is_empty() && !secret.is_empty() {
            if let Err(e) =
                crate::config::store_cloud_password(&format!("ldap:{}", dir.password_key), &secret)
            {
                error(
                    &message,
                    &format!("{}: {e}", i18n("Could not save password")),
                );
                return;
            }
        }
        if let Some(old) = old {
            if !old.password_key.is_empty() && old.password_key != dir.password_key {
                crate::config::delete_cloud_password(&format!("ldap:{}", old.password_key));
            }
        }
        refresh(&list, &status, &parent);
        win.close();
    });
    window.present();
}

pub fn page() -> adw::PreferencesPage {
    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::new();
    group.set_title(&i18n("LDAP Directories"));
    group.set_description(Some(&i18n("Optional recipient suggestions from your organization's directory. Passwords are stored in the system keyring.")));
    let add = gtk::Button::with_label(&i18n("Add directory"));
    add.set_halign(gtk::Align::Start);
    group.set_header_suffix(Some(&add));
    let status = gtk::Label::new(None);
    status.set_wrap(true);
    status.set_visible(false);
    group.add(&status);
    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    group.add(&list);
    page.add(&group);
    let parent = page.clone().upcast::<gtk::Widget>();
    refresh(&list, &status, &parent);
    add.connect_clicked(move |_| edit_directory(&parent, &list, &status, None));
    page
}
