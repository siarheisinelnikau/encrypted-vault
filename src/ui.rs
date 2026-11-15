//! Native Win32 controls and CPU GDI drawing. GetMessage sleeps between real events.
use crate::{
    app::{Backend, Command, Event, Snapshot},
    dokan,
    error::Result,
    i18n::text,
    preferences::{self, Language, Preferences, Theme},
    updates,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    ffi::c_void,
    path::PathBuf,
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::{Dwm::DwmSetWindowAttribute, Gdi::*},
    System::{
        Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize},
        LibraryLoader::GetModuleHandleW,
        Threading::CreateMutexW,
    },
    UI::{
        Controls::*,
        HiDpi::*,
        Input::KeyboardAndMouse::{EnableWindow, SetFocus},
        Shell::*,
        WindowsAndMessaging::*,
    },
};
use zeroize::Zeroizing;

const WAKE: u32 = WM_APP + 1;
const RESTORE: u32 = WM_APP + 2;
const TRAY: u32 = WM_APP + 3;
const EXIT: u32 = WM_APP + 4;
const SS_LEFT: u32 = 0;
const ANIMATION: usize = 1;
const PRIMARY: u16 = 100;
const OPEN_DRIVE: u16 = 101;
const CREATE: u16 = 102;
const OPEN: u16 = 103;
const FORGET: u16 = 104;
const SETTINGS: u16 = 105;
const BACK: u16 = 106;
const LIST: u16 = 110;
const SUBMIT: u16 = 120;
const PATH: u16 = 121;
const BROWSE: u16 = 122;
const PASSWORD: u16 = 123;
const CONFIRM: u16 = 124;
const DRIVE: u16 = 125;
const ACK: u16 = 126;
const LANGUAGE: u16 = 200;
const THEME: u16 = 201;
const REDUCED: u16 = 202;
const IDLE: u16 = 203;
const STARTUP: u16 = 204;
const CHECK: u16 = 205;
const DOWNLOAD: u16 = 206;
const RECOVERY: u16 = 207;
const QUIT: u16 = 208;
const LOCK_ALL: u16 = 209;
const MESSAGE: u16 = 900;

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Home,
    Add(bool),
    Unlock(usize),
    Settings,
}
#[derive(Clone)]
enum UpdateView {
    Idle,
    Checking,
    Current,
    Available(updates::Available),
    Downloading(u8),
    Failed,
    Ready,
}
#[derive(Clone, Copy)]
struct Palette {
    background: u32,
    surface: u32,
    text: u32,
    muted: u32,
    line: u32,
    accent: u32,
    accent_text: u32,
    selected: u32,
    error: u32,
}
const fn rgb(r: u32, g: u32, b: u32) -> u32 {
    r | (g << 8) | (b << 16)
}
impl Palette {
    fn for_theme(theme: Theme) -> Self {
        match theme {
            Theme::Light => Self {
                background: rgb(245, 246, 252),
                surface: rgb(255, 255, 255),
                text: rgb(32, 35, 57),
                muted: rgb(89, 97, 120),
                line: rgb(213, 218, 233),
                accent: rgb(88, 74, 221),
                accent_text: rgb(255, 255, 255),
                selected: rgb(232, 230, 255),
                error: rgb(163, 39, 55),
            },
            Theme::Dark => Self {
                background: rgb(21, 24, 36),
                surface: rgb(32, 37, 53),
                text: rgb(242, 243, 255),
                muted: rgb(174, 183, 205),
                line: rgb(67, 75, 98),
                accent: rgb(182, 165, 255),
                accent_text: rgb(24, 21, 41),
                selected: rgb(55, 48, 85),
                error: rgb(255, 157, 169),
            },
        }
    }
}
#[derive(Clone, Copy)]
struct Placement {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}
struct Control {
    hwnd: HWND,
    placement: Placement,
}
struct UiCell {
    state: RefCell<Ui>,
    pending_wake: Cell<bool>,
    pending_restore: Cell<bool>,
}
struct Ui {
    hwnd: HWND,
    icon: HICON,
    small_icon: HICON,
    font: HFONT,
    title_font: HFONT,
    small_font: HFONT,
    background: HBRUSH,
    surface: HBRUSH,
    controls: BTreeMap<u16, Control>,
    next_label: u16,
    snapshot: Snapshot,
    backend: Option<Backend>,
    page: Page,
    selected: usize,
    path: String,
    message: &'static str,
    message_error: bool,
    busy: bool,
    dirty: bool,
    return_home: bool,
    update: UpdateView,
    tray_added: bool,
    tray_tip: String,
    taskbar_message: u32,
    animation: Option<Instant>,
    system_motion: bool,
    paints: u64,
    capture_mode: bool,
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn class_name() -> Vec<u16> {
    wide("EncryptedVault.Main.0.1")
}

impl Ui {
    fn t(&self, key: &str) -> &'static str {
        text(self.snapshot.preferences.language, key)
    }
    fn palette(&self) -> Palette {
        Palette::for_theme(self.snapshot.preferences.theme)
    }
    fn scale(&self, n: i32) -> i32 {
        ((n as i64 * unsafe { GetDpiForWindow(self.hwnd) }.max(96) as i64 + 48) / 96) as i32
    }
    fn logical_size(&self) -> (i32, i32) {
        let mut r = RECT::default();
        unsafe {
            GetClientRect(self.hwnd, &mut r);
        }
        (self.unscale(r.right), self.unscale(r.bottom))
    }
    fn unscale(&self, n: i32) -> i32 {
        (n as i64 * 96 / unsafe { GetDpiForWindow(self.hwnd) }.max(96) as i64) as i32
    }
    fn visible(&self) -> bool {
        self.capture_mode || unsafe { IsWindowVisible(self.hwnd) != 0 && IsIconic(self.hwnd) == 0 }
    }
    fn handle(&self, id: u16) -> HWND {
        self.controls.get(&id).map_or(ptr::null_mut(), |c| c.hwnd)
    }
    fn selected_vault(&self) -> Option<&crate::preferences::RecentVault> {
        self.snapshot.preferences.vaults.get(self.selected)
    }
    fn mounted_letter(&self) -> Option<char> {
        self.selected_vault()
            .and_then(|v| self.snapshot.mounted.get(&v.path))
            .copied()
    }

    fn setup_resources(&mut self) {
        unsafe {
            for font in [self.font, self.title_font, self.small_font] {
                if !font.is_null() {
                    DeleteObject(font);
                }
            }
            for brush in [self.background, self.surface] {
                if !brush.is_null() {
                    DeleteObject(brush);
                }
            }
            let name = wide("Segoe UI");
            self.font = CreateFontW(
                -self.scale(15),
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH as u32,
                name.as_ptr(),
            );
            self.title_font = CreateFontW(
                -self.scale(24),
                0,
                0,
                0,
                600,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH as u32,
                name.as_ptr(),
            );
            self.small_font = CreateFontW(
                -self.scale(13),
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH as u32,
                name.as_ptr(),
            );
            self.background = CreateSolidBrush(self.palette().background);
            self.surface = CreateSolidBrush(self.palette().surface);
            let dark: i32 = (self.snapshot.preferences.theme == Theme::Dark) as i32;
            DwmSetWindowAttribute(self.hwnd, 20, &dark as *const _ as _, 4);
        }
    }
    fn add(
        &mut self,
        id: u16,
        class: &str,
        label: &str,
        style: u32,
        placement: Placement,
        font: HFONT,
    ) -> HWND {
        let class = wide(class);
        let label = wide(label);
        let control = unsafe {
            CreateWindowExW(
                if class[0] == b'E' as u16 {
                    WS_EX_CLIENTEDGE
                } else {
                    0
                },
                class.as_ptr(),
                label.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                0,
                0,
                1,
                1,
                self.hwnd,
                id as usize as _,
                GetModuleHandleW(ptr::null()),
                ptr::null(),
            )
        };
        unsafe {
            SendMessageW(control, WM_SETFONT, font as usize, 0);
        }
        self.controls.insert(
            id,
            Control {
                hwnd: control,
                placement,
            },
        );
        control
    }
    fn label(&mut self, label: &str, x: i32, y: i32, w: i32, h: i32, small: bool) {
        let id = self.next_label;
        self.next_label += 1;
        self.add(
            id,
            "STATIC",
            label,
            SS_LEFT,
            Placement { x, y, w, h },
            if small { self.small_font } else { self.font },
        );
    }
    fn title(&mut self, key: &str) {
        let id = self.next_label;
        self.next_label += 1;
        self.add(
            id,
            "STATIC",
            self.t(key),
            SS_LEFT,
            Placement {
                x: 28,
                y: 108,
                w: -56,
                h: 36,
            },
            self.title_font,
        );
    }
    fn button(&mut self, id: u16, key: &str, x: i32, y: i32, w: i32, h: i32) {
        let handle = self.add(
            id,
            "BUTTON",
            self.t(key),
            WS_TABSTOP | BS_OWNERDRAW as u32,
            Placement { x, y, w, h },
            self.font,
        );
        if (self.busy || matches!(self.update, UpdateView::Downloading(_) | UpdateView::Ready))
            && ![BACK, SETTINGS, RECOVERY].contains(&id)
        {
            unsafe {
                EnableWindow(handle, 0);
            }
        }
    }
    fn edit(&mut self, id: u16, value: &str, x: i32, y: i32, w: i32, secret: bool) {
        let handle = self.add(
            id,
            "EDIT",
            value,
            WS_TABSTOP | ES_AUTOHSCROLL as u32 | if secret { ES_PASSWORD as u32 } else { 0 },
            Placement { x, y, w, h: 36 },
            self.font,
        );
        unsafe {
            SendMessageW(
                handle,
                EM_SETLIMITTEXT,
                if secret { 1024 } else { 32760 },
                0,
            );
            if secret {
                SendMessageW(handle, EM_SETPASSWORDCHAR, 0x2022, 0);
            }
            if self.busy {
                EnableWindow(handle, 0);
            }
        }
    }
    fn checkbox(&mut self, id: u16, key: &str, checked: bool, y: i32, h: i32) {
        let handle = self.add(
            id,
            "BUTTON",
            self.t(key),
            WS_TABSTOP | BS_AUTOCHECKBOX as u32 | BS_MULTILINE as u32,
            Placement {
                x: 28,
                y,
                w: -56,
                h,
            },
            self.font,
        );
        unsafe {
            SendMessageW(handle, BM_SETCHECK, checked as usize, 0);
            if self.busy {
                EnableWindow(handle, 0);
            }
        }
    }
    fn combo(&mut self, id: u16, values: &[String], selected: usize, x: i32, y: i32, w: i32) {
        let handle = self.add(
            id,
            "COMBOBOX",
            "",
            WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32 | CBS_HASSTRINGS as u32,
            Placement { x, y, w, h: 240 },
            self.font,
        );
        unsafe {
            for value in values {
                let value = wide(value);
                SendMessageW(handle, CB_ADDSTRING, 0, value.as_ptr() as isize);
            }
            SendMessageW(handle, CB_SETCURSEL, selected, 0);
            SendMessageW(
                handle,
                CB_SETITEMHEIGHT,
                usize::MAX,
                self.scale(28) as isize,
            );
            if self.busy {
                EnableWindow(handle, 0);
            }
        }
    }
    fn drive_combo(&mut self, y: i32) {
        let letters = if self.page == Page::Settings {
            ('D'..='Z').collect()
        } else if self.capture_mode {
            vec!['V', 'W']
        } else {
            dokan::available_letters()
        };
        let selected = letters
            .iter()
            .position(|l| *l == self.snapshot.preferences.preferred_letter)
            .unwrap_or(0);
        let values: Vec<_> = letters.into_iter().map(|l| format!("{l}:\\")).collect();
        self.combo(DRIVE, &values, selected, 28, y, 168);
    }
    fn rebuild(&mut self) {
        if !self.visible() {
            self.dirty = true;
            return;
        }
        self.build_controls();
        self.animate();
    }
    fn build_controls(&mut self) {
        self.clear_secrets();
        for (_, control) in std::mem::take(&mut self.controls) {
            unsafe {
                DestroyWindow(control.hwnd);
            }
        }
        self.next_label = 1000;
        self.button(
            if self.page == Page::Home {
                SETTINGS
            } else {
                BACK
            },
            if self.page == Page::Home {
                "settings"
            } else {
                "back"
            },
            -180,
            28,
            152,
            36,
        );
        match self.page {
            Page::Home => self.home(),
            Page::Add(create) => self.add_page(create),
            Page::Unlock(index) => self.unlock_page(index),
            Page::Settings => self.settings_page(),
        }
        if self.page != Page::Settings {
            self.add(
                MESSAGE,
                "STATIC",
                self.t(self.message),
                SS_LEFT,
                Placement {
                    x: 28,
                    y: if self.page == Page::Home { -224 } else { -132 },
                    w: -56,
                    h: 48,
                },
                self.font,
            );
        }
        self.label(self.t("footer_tray"), 28, -26, -56, 22, true);
        self.layout();
        self.dirty = false;
        unsafe {
            InvalidateRect(self.hwnd, ptr::null(), 0);
        }
    }
    fn home(&mut self) {
        self.title("home_title");
        self.label(self.t("home_hint"), 28, 150, -56, 44, false);
        if self.snapshot.preferences.vaults.is_empty() {
            self.label(self.t("empty_title"), 44, 254, -88, 36, false);
            self.label(self.t("empty_hint"), 44, 300, -88, 78, false);
        } else {
            let list = self.add(
                LIST,
                "LISTBOX",
                "",
                WS_TABSTOP
                    | WS_VSCROLL
                    | LBS_NOTIFY as u32
                    | LBS_OWNERDRAWFIXED as u32
                    | LBS_HASSTRINGS as u32
                    | LBS_NOINTEGRALHEIGHT as u32,
                Placement {
                    x: 28,
                    y: 208,
                    w: -56,
                    h: -480,
                },
                self.font,
            );
            unsafe {
                for vault in &self.snapshot.preferences.vaults {
                    let state = if self.snapshot.mounted.contains_key(&vault.path) {
                        self.t("unlocked")
                    } else {
                        self.t("locked")
                    };
                    let label = wide(&format!("{} · {}", vault.alias, state));
                    SendMessageW(list, LB_ADDSTRING, 0, label.as_ptr() as isize);
                }
                self.selected = self
                    .selected
                    .min(self.snapshot.preferences.vaults.len() - 1);
                SendMessageW(list, LB_SETCURSEL, self.selected, 0);
                SendMessageW(list, LB_SETITEMHEIGHT, 0, self.scale(72) as isize);
            }
            self.button(FORGET, "forget", 28, -264, 280, 28);
            if self.mounted_letter().is_some() {
                unsafe {
                    EnableWindow(self.handle(FORGET), 0);
                }
            }
        }
        self.button(
            PRIMARY,
            if self.mounted_letter().is_some() {
                "lock"
            } else {
                "unlock"
            },
            28,
            -168,
            -240,
            42,
        );
        self.button(OPEN_DRIVE, "open_drive", -192, -168, 164, 42);
        self.button(CREATE, "create", 28, -108, 288, 38);
        self.button(OPEN, "open_existing", -324, -108, 296, 38);
        unsafe {
            if self.snapshot.preferences.vaults.is_empty() {
                EnableWindow(self.handle(PRIMARY), 0);
            }
            if self.mounted_letter().is_none() {
                EnableWindow(self.handle(OPEN_DRIVE), 0);
            }
        }
    }
    fn path_field(&mut self, y: i32) {
        self.label(self.t("path_label"), 28, y, -56, 22, false);
        let value = self.path.clone();
        self.edit(PATH, &value, 28, y + 26, -212, false);
        self.button(BROWSE, "browse", -168, y + 26, 140, 36);
    }
    fn add_page(&mut self, create: bool) {
        self.title(if create { "create_title" } else { "open_title" });
        self.label(
            &if create {
                format!("{}\n{}", self.t("create_hint"), self.t("single_writer"))
            } else {
                self.t("open_hint").into()
            },
            28,
            150,
            -56,
            56,
            true,
        );
        self.path_field(210);
        if create {
            self.label(self.t("password_label"), 28, 284, -56, 22, false);
            self.edit(PASSWORD, "", 28, 308, -56, true);
            self.label(self.t("confirm_label"), 28, 358, -56, 22, false);
            self.edit(CONFIRM, "", 28, 382, -56, true);
            self.label(self.t("drive_label"), 28, 432, -56, 22, false);
            self.drive_combo(456);
            self.label(self.t("recovery_warning"), 28, 500, -56, 40, true);
            self.checkbox(ACK, "confirm_ack", false, 544, 40);
        } else {
            self.label(self.t("recovery_text"), 28, 306, -56, 84, false);
            self.label(self.t("single_writer"), 28, 422, -56, 64, false);
            self.label(self.t("security_note"), 28, 534, -56, 40, true);
        }
        self.button(
            SUBMIT,
            if create {
                "create_action"
            } else {
                "open_action"
            },
            28,
            -72,
            -56,
            42,
        );
    }
    fn unlock_page(&mut self, index: usize) {
        self.title("unlock_title");
        if let Some(vault) = self.snapshot.preferences.vaults.get(index) {
            let alias = vault.alias.clone();
            let path = vault.path.to_string_lossy().into_owned();
            self.label(&alias, 28, 156, -56, 36, false);
            self.label(&path, 28, 202, -56, 70, true);
        }
        self.label(self.t("password_label"), 28, 300, -56, 22, false);
        self.edit(PASSWORD, "", 28, 328, -56, true);
        self.label(self.t("drive_label"), 28, 394, -56, 22, false);
        self.drive_combo(420);
        self.label(self.t("single_writer"), 28, 480, -56, 64, false);
        self.label(self.t("recovery_warning"), 28, 552, -56, 50, true);
        self.button(SUBMIT, "unlock_action", 28, -72, -56, 42);
    }
    fn settings_page(&mut self) {
        self.title("settings_title");
        self.label(self.t("language_label"), 28, 166, 280, 22, false);
        self.label(self.t("theme_label"), 340, 166, -368, 22, false);
        self.combo(
            LANGUAGE,
            &Language::ALL.map(|l| l.native_name().to_string()),
            Language::ALL
                .iter()
                .position(|l| *l == self.snapshot.preferences.language)
                .unwrap_or(0),
            28,
            192,
            280,
        );
        self.combo(
            THEME,
            &[self.t("light").into(), self.t("dark").into()],
            (self.snapshot.preferences.theme == Theme::Dark) as usize,
            340,
            192,
            -368,
        );
        self.checkbox(
            REDUCED,
            "reduced_motion",
            self.snapshot.preferences.reduced_motion,
            238,
            32,
        );
        self.label(self.t("drive_label"), 28, 292, 168, 22, false);
        self.drive_combo(318);
        self.label(self.t("idle_label"), 228, 292, -256, 22, false);
        let idle_keys = [
            "never",
            "minutes_5",
            "minutes_15",
            "minutes_30",
            "minutes_60",
        ];
        self.combo(
            IDLE,
            &idle_keys.map(|k| self.t(k).into()),
            [0, 5, 15, 30, 60]
                .iter()
                .position(|v| *v == self.snapshot.preferences.idle_minutes)
                .unwrap_or(0),
            228,
            318,
            -256,
        );
        self.label(
            self.t(if dokan::runtime_present() {
                "runtime_ready"
            } else {
                "runtime_missing"
            }),
            28,
            362,
            -56,
            44,
            true,
        );
        self.label(
            &format!(
                "{}  ·  {} {}",
                self.t("updates_title"),
                self.t("version_label"),
                updates::VERSION
            ),
            28,
            420,
            -56,
            28,
            false,
        );
        self.checkbox(
            STARTUP,
            "startup_updates",
            self.snapshot.preferences.startup_updates,
            456,
            32,
        );
        self.button(CHECK, "check_updates", 28, 504, 276, 42);
        self.button(DOWNLOAD, "download_install", -340, 504, 312, 42);
        unsafe {
            if !matches!(self.update, UpdateView::Available(_)) || !self.snapshot.mounted.is_empty()
            {
                EnableWindow(self.handle(DOWNLOAD), 0);
            }
            if matches!(
                self.update,
                UpdateView::Checking | UpdateView::Downloading(_) | UpdateView::Ready
            ) {
                EnableWindow(self.handle(CHECK), 0);
            }
        }
        let update_text = self.update_text();
        self.add(
            MESSAGE,
            "STATIC",
            if self.message_error {
                self.t(self.message)
            } else {
                &update_text
            },
            SS_LEFT,
            Placement {
                x: 28,
                y: 560,
                w: -56,
                h: 72,
            },
            self.font,
        );
        self.button(RECOVERY, "recovery_title", 28, -72, 288, 38);
        self.button(QUIT, "quit", -188, -72, 160, 38);
    }
    fn update_text(&self) -> String {
        match &self.update {
            UpdateView::Idle => self.t("update_idle").into(),
            UpdateView::Checking => self.t("update_checking").into(),
            UpdateView::Current => self.t("update_current").into(),
            UpdateView::Available(a) => format!(
                "{} {}{}",
                self.t("update_available"),
                a.version,
                if self.snapshot.mounted.is_empty() {
                    String::new()
                } else {
                    format!("\n{}", self.t("install_lock_first"))
                }
            ),
            UpdateView::Downloading(p) => format!("{} {p}%", self.t("update_downloading")),
            UpdateView::Failed => self.t("update_failed").into(),
            UpdateView::Ready => self.t("update_ready").into(),
        }
    }
    fn layout(&self) {
        let (cw, ch) = self.logical_size();
        unsafe {
            for control in self.controls.values() {
                let r = control.placement;
                let x = if r.x < 0 { cw + r.x } else { r.x };
                let y = if r.y < 0 { ch + r.y } else { r.y };
                let w = if r.w < 0 { cw + r.w } else { r.w };
                let h = if r.h < 0 { ch + r.h } else { r.h };
                MoveWindow(
                    control.hwnd,
                    self.scale(x),
                    self.scale(y),
                    self.scale(w.max(1)),
                    self.scale(h.max(1)),
                    1,
                );
            }
        }
    }
    fn animate(&mut self) {
        unsafe {
            KillTimer(self.hwnd, ANIMATION);
        }
        self.animation = None;
        if self.visible() && !self.snapshot.preferences.reduced_motion && self.system_motion {
            self.animation = Some(Instant::now());
            unsafe {
                SetTimer(self.hwnd, ANIMATION, 16, None);
            }
        }
    }
    fn set_message(&mut self, key: &'static str, error: bool) {
        self.message = key;
        self.message_error = error;
        self.refresh_message();
        self.animate();
    }
    fn refresh_message(&mut self) {
        if !self.visible() {
            self.dirty = true;
            return;
        }
        let value = if !self.message_error
            && (self.page == Page::Settings
                || (self.page == Page::Home && matches!(self.update, UpdateView::Available(_))))
        {
            self.update_text()
        } else {
            self.t(self.message).into()
        };
        unsafe {
            SetWindowTextW(self.handle(MESSAGE), wide(&value).as_ptr());
            InvalidateRect(self.handle(MESSAGE), ptr::null(), 1);
        }
    }
    fn input(&self, id: u16) -> String {
        let handle = self.handle(id);
        if handle.is_null() {
            return String::new();
        }
        let length = unsafe { GetWindowTextLengthW(handle) }.max(0) as usize;
        let mut value = vec![0u16; length + 1];
        unsafe {
            GetWindowTextW(handle, value.as_mut_ptr(), value.len() as i32);
        }
        String::from_utf16_lossy(&value[..length])
    }
    fn secret(&self, id: u16) -> Zeroizing<String> {
        let handle = self.handle(id);
        let mut value = Zeroizing::new(vec![0u16; 1025]);
        let length = unsafe { GetWindowTextW(handle, value.as_mut_ptr(), value.len() as i32) }
            .max(0) as usize;
        Zeroizing::new(String::from_utf16_lossy(&value[..length]))
    }
    fn clear_secrets(&self) {
        unsafe {
            for id in [PASSWORD, CONFIRM] {
                let handle = self.handle(id);
                if !handle.is_null() {
                    SetWindowTextW(handle, wide("").as_ptr());
                    SendMessageW(handle, EM_EMPTYUNDOBUFFER, 0, 0);
                }
            }
        }
    }
    fn check(&self, id: u16) -> bool {
        unsafe { SendMessageW(self.handle(id), BM_GETCHECK, 0, 0) == BST_CHECKED as isize }
    }
    fn choice(&self, id: u16) -> usize {
        unsafe { SendMessageW(self.handle(id), CB_GETCURSEL, 0, 0).max(0) as usize }
    }
    fn drive(&self) -> Option<char> {
        let mut buffer = [0u16; 16];
        unsafe {
            SendMessageW(
                self.handle(DRIVE),
                WM_GETTEXT,
                buffer.len(),
                buffer.as_mut_ptr() as isize,
            );
        }
        char::from_u32(buffer[0] as u32).filter(|c| ('D'..='Z').contains(c))
    }
    fn dispatch(&mut self, command: Command, return_home: bool) {
        let Some(backend) = &self.backend else {
            return;
        };
        if backend.commands.try_send(command).is_err() {
            self.set_message("queue_full", true);
            return;
        }
        self.busy = true;
        self.return_home = return_home;
        self.set_message("busy", false);
        unsafe {
            for (id, c) in &self.controls {
                if *id < 900 && ![BACK, SETTINGS, RECOVERY].contains(id) {
                    EnableWindow(c.hwnd, 0);
                }
            }
        }
    }
    fn submit(&mut self) {
        if self.busy {
            return;
        }
        match self.page {
            Page::Add(create) => {
                let path = self.input(PATH);
                self.path = path.clone();
                let path = PathBuf::from(path.trim());
                if !path.is_absolute() {
                    self.set_message("error_path", true);
                    return;
                }
                let alias = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if alias.is_empty() || alias.chars().count() > 80 {
                    self.set_message("error_alias", true);
                    return;
                }
                if create {
                    let password = self.secret(PASSWORD);
                    let confirm = self.secret(CONFIRM);
                    if password.chars().count() < 12 {
                        self.set_message("error_password_short", true);
                        return;
                    }
                    if *password != *confirm {
                        self.set_message("error_password_mismatch", true);
                        return;
                    }
                    if !self.check(ACK) {
                        self.set_message("error_ack", true);
                        return;
                    }
                    let Some(letter) = self.drive() else {
                        self.set_message("error_drive", true);
                        return;
                    };
                    self.clear_secrets();
                    self.dispatch(
                        Command::Create {
                            path,
                            alias,
                            password,
                            letter,
                        },
                        true,
                    );
                } else {
                    self.dispatch(Command::Remember { path, alias }, true);
                }
            }
            Page::Unlock(index) => {
                let Some(vault) = self.snapshot.preferences.vaults.get(index) else {
                    return;
                };
                let path = vault.path.clone();
                let password = self.secret(PASSWORD);
                let Some(letter) = self.drive() else {
                    self.set_message("error_drive", true);
                    return;
                };
                self.clear_secrets();
                self.dispatch(
                    Command::Unlock {
                        path,
                        password,
                        letter,
                    },
                    true,
                );
            }
            _ => (),
        }
    }
    fn save_settings(&mut self) {
        if self.busy {
            return;
        }
        let mut p = self.snapshot.preferences.clone();
        p.language = Language::ALL[self.choice(LANGUAGE).min(5)];
        p.theme = if self.choice(THEME) == 1 {
            Theme::Dark
        } else {
            Theme::Light
        };
        p.reduced_motion = self.check(REDUCED);
        p.startup_updates = self.check(STARTUP);
        p.idle_minutes = [0, 5, 15, 30, 60][self.choice(IDLE).min(4)];
        if let Some(letter) = self.drive() {
            p.preferred_letter = letter;
        }
        let theme_changed = p.theme != self.snapshot.preferences.theme;
        self.snapshot.preferences = p.clone();
        if theme_changed {
            self.setup_resources();
        }
        self.update_tray();
        self.dispatch(Command::Save(p), false);
        self.rebuild();
    }
    fn navigate(&mut self, page: Page) {
        self.clear_secrets();
        self.path = String::new();
        self.page = page;
        self.message = "security_note";
        self.message_error = false;
        self.rebuild();
        unsafe {
            if matches!(page, Page::Unlock(_)) {
                SetFocus(self.handle(PASSWORD));
            } else if matches!(page, Page::Add(_)) {
                SetFocus(self.handle(PATH));
            }
        }
    }
    fn command(&mut self, id: u16, notification: u16) {
        if matches!(self.update, UpdateView::Downloading(_) | UpdateView::Ready)
            && ![BACK, SETTINGS, RECOVERY, QUIT].contains(&id)
        {
            return;
        }
        if [LANGUAGE, THEME, IDLE, DRIVE].contains(&id)
            && notification == CBN_SELCHANGE as u16
            && self.page == Page::Settings
        {
            self.save_settings();
            return;
        }
        if [REDUCED, STARTUP].contains(&id) && self.page == Page::Settings {
            self.save_settings();
            return;
        }
        match id {
            1 => self.submit(),
            2 => {
                if self.page == Page::Home {
                    unsafe {
                        PostMessageW(self.hwnd, WM_CLOSE, 0, 0);
                    }
                } else {
                    self.navigate(Page::Home);
                }
            }
            SETTINGS => self.navigate(Page::Settings),
            BACK => self.navigate(Page::Home),
            CREATE => self.navigate(Page::Add(true)),
            OPEN => self.navigate(Page::Add(false)),
            PRIMARY => {
                if self.busy {
                    return;
                }
                if let Some(vault) = self.selected_vault() {
                    if self.mounted_letter().is_some() {
                        self.dispatch(Command::Lock(vault.path.clone()), false);
                    } else {
                        self.navigate(Page::Unlock(self.selected));
                    }
                }
            }
            OPEN_DRIVE => {
                if let Some(letter) = self.mounted_letter() {
                    let result = unsafe {
                        ShellExecuteW(
                            self.hwnd,
                            wide("open").as_ptr(),
                            wide(&format!("{letter}:\\")).as_ptr(),
                            ptr::null(),
                            ptr::null(),
                            SW_SHOWNORMAL,
                        )
                    };
                    if result as isize <= 32 {
                        self.set_message("error_mount", true);
                    }
                }
            }
            FORGET => {
                if !self.busy
                    && let Some(vault) = self.selected_vault()
                {
                    self.dispatch(Command::Forget(vault.path.clone()), false);
                }
            }
            SUBMIT => self.submit(),
            BROWSE => self.browse(),
            LIST if notification == LBN_SELCHANGE as u16 => {
                self.selected =
                    unsafe { SendMessageW(self.handle(LIST), LB_GETCURSEL, 0, 0) }.max(0) as usize;
                let label = wide(self.t(if self.mounted_letter().is_some() {
                    "lock"
                } else {
                    "unlock"
                }));
                unsafe {
                    SetWindowTextW(self.handle(PRIMARY), label.as_ptr());
                    EnableWindow(
                        self.handle(OPEN_DRIVE),
                        (self.mounted_letter().is_some() && !self.busy) as i32,
                    );
                    EnableWindow(
                        self.handle(FORGET),
                        (self.mounted_letter().is_none() && !self.busy) as i32,
                    );
                }
            }
            CHECK => {
                if !matches!(
                    self.update,
                    UpdateView::Checking | UpdateView::Downloading(_) | UpdateView::Ready
                ) {
                    self.update = UpdateView::Checking;
                    self.message_error = false;
                    if let Some(backend) = &self.backend {
                        backend.check_updates(false);
                    }
                    self.rebuild();
                }
            }
            DOWNLOAD => {
                if self.busy || !self.snapshot.mounted.is_empty() {
                    self.set_message("install_lock_first", true);
                    return;
                }
                if let UpdateView::Available(available) = &self.update {
                    match std::env::current_exe() {
                        Ok(target) => {
                            if let Some(backend) = &self.backend {
                                backend.download(available.clone(), target);
                            }
                            self.update = UpdateView::Downloading(0);
                            self.message_error = false;
                            self.rebuild();
                        }
                        Err(_) => self.set_message("error_update", true),
                    }
                }
            }
            RECOVERY => unsafe {
                MessageBoxW(
                    self.hwnd,
                    wide(self.t("recovery_text")).as_ptr(),
                    wide(self.t("recovery_title")).as_ptr(),
                    MB_OK | MB_ICONINFORMATION,
                );
            },
            QUIT => {
                if !self.busy {
                    self.dispatch(Command::Quit, false);
                }
            }
            LOCK_ALL if !self.busy => self.dispatch(Command::LockAll, false),
            _ => (),
        }
    }
    fn browse(&mut self) {
        let mut display = [0u16; 260];
        let title = wide(self.t("folder_picker"));
        let info = BROWSEINFOW {
            hwndOwner: self.hwnd,
            pidlRoot: ptr::null_mut(),
            pszDisplayName: display.as_mut_ptr(),
            lpszTitle: title.as_ptr(),
            ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
            lpfn: None,
            lParam: 0,
            iImage: 0,
        };
        let item = unsafe { SHBrowseForFolderW(&info) };
        if item.is_null() {
            return;
        }
        let mut path = [0u16; 260];
        let ok = unsafe { SHGetPathFromIDListW(item, path.as_mut_ptr()) };
        unsafe {
            CoTaskMemFree(item as _);
        }
        if ok != 0 {
            let length = path.iter().position(|c| *c == 0).unwrap_or(path.len());
            let mut path = PathBuf::from(String::from_utf16_lossy(&path[..length]));
            if self.page == Page::Add(true) {
                path = path.join("Encrypted Vault");
            }
            self.path = path.to_string_lossy().into_owned();
            unsafe {
                SetWindowTextW(self.handle(PATH), wide(&self.path).as_ptr());
            }
        }
    }
    fn drain(&mut self) {
        let mut events = Vec::new();
        if let Some(backend) = &self.backend {
            while let Ok(event) = backend.events.try_recv() {
                events.push(event);
            }
        }
        let mut rebuild = false;
        for event in events {
            match event {
                Event::Finished {
                    snapshot,
                    message,
                    error,
                } => {
                    let newly_added =
                        snapshot.preferences.vaults.len() > self.snapshot.preferences.vaults.len();
                    let theme_changed =
                        snapshot.preferences.theme != self.snapshot.preferences.theme;
                    self.snapshot = snapshot;
                    self.busy = false;
                    self.message = message;
                    self.message_error = error;
                    if self.return_home && (!error || newly_added) {
                        self.page = Page::Home;
                        self.selected = self.snapshot.preferences.vaults.len().saturating_sub(1);
                    }
                    self.return_home = false;
                    if theme_changed && self.visible() {
                        self.setup_resources();
                    }
                    self.update_tray();
                    rebuild = true;
                }
                Event::UpdateChecked(result, silent) => {
                    self.update = match result {
                        Ok(Some(a)) => UpdateView::Available(a),
                        Ok(None) => UpdateView::Current,
                        Err(_) => UpdateView::Failed,
                    };
                    if !silent {
                        self.message_error = false;
                    }
                }
                Event::DownloadProgress(p) => self.update = UpdateView::Downloading(p),
                Event::Downloaded(result) => match result {
                    Ok(staged) => {
                        if !self.snapshot.mounted.is_empty() || self.busy {
                            self.message = "install_lock_first";
                            self.message_error = true;
                            self.update = UpdateView::Failed;
                        } else if updates::spawn_installer(&staged).is_ok() {
                            self.update = UpdateView::Ready;
                            unsafe {
                                PostMessageW(self.hwnd, EXIT, 0, 0);
                            }
                            return;
                        } else {
                            self.message = "error_update";
                            self.message_error = true;
                            self.update = UpdateView::Failed;
                        }
                    }
                    Err(_) => {
                        self.update = UpdateView::Failed;
                        self.message = "error_update";
                        self.message_error = true;
                    }
                },
                Event::QuitAllowed => {
                    unsafe {
                        PostMessageW(self.hwnd, EXIT, 0, 0);
                    }
                    return;
                }
            }
        }
        if rebuild {
            self.rebuild();
        } else {
            self.refresh_message();
            if self.page == Page::Settings && self.visible() {
                self.refresh_update_buttons();
            }
        }
    }
    fn refresh_update_buttons(&self) {
        unsafe {
            EnableWindow(
                self.handle(CHECK),
                (!matches!(
                    self.update,
                    UpdateView::Checking | UpdateView::Downloading(_) | UpdateView::Ready
                ) && !self.busy) as i32,
            );
            EnableWindow(
                self.handle(DOWNLOAD),
                (matches!(self.update, UpdateView::Available(_))
                    && self.snapshot.mounted.is_empty()
                    && !self.busy) as i32,
            );
        }
    }
    fn update_tray(&mut self) {
        if self.capture_mode {
            return;
        }
        let tip = format!(
            "Encrypted Vault · {} {}",
            self.snapshot.mounted.len(),
            self.t("unlocked")
        );
        if self.tray_added && tip == self.tray_tip {
            return;
        }
        let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.hwnd;
        data.uID = 1;
        data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        data.uCallbackMessage = TRAY;
        data.hIcon = self.small_icon;
        for (dst, src) in data.szTip.iter_mut().take(127).zip(tip.encode_utf16()) {
            *dst = src;
        }
        let ok =
            unsafe { Shell_NotifyIconW(if self.tray_added { NIM_MODIFY } else { NIM_ADD }, &data) };
        if ok != 0 {
            self.tray_added = true;
            self.tray_tip = tip;
        }
    }
    fn restore(&mut self) {
        unsafe {
            ShowWindow(
                self.hwnd,
                if IsIconic(self.hwnd) != 0 {
                    SW_RESTORE
                } else {
                    SW_SHOW
                },
            );
            SetForegroundWindow(self.hwnd);
        }
        if self.dirty {
            self.setup_resources();
            self.build_controls();
        }
        self.animate();
    }
    fn tray_menu(&mut self) {
        unsafe {
            let menu = CreatePopupMenu();
            for (id, key) in [
                (BACK, "home_title"),
                (LOCK_ALL, "lock_all"),
                (SETTINGS, "settings"),
                (QUIT, "quit"),
            ] {
                AppendMenuW(menu, MF_STRING, id as usize, wide(self.t(key)).as_ptr());
            }
            let mut point = POINT::default();
            GetCursorPos(&mut point);
            SetForegroundWindow(self.hwnd);
            let id = TrackPopupMenuEx(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                point.x,
                point.y,
                self.hwnd,
                ptr::null(),
            ) as u16;
            DestroyMenu(menu);
            PostMessageW(self.hwnd, WM_NULL, 0, 0);
            if [BACK, SETTINGS].contains(&id) {
                self.restore();
            }
            if id != 0 {
                self.command(id, 0);
            }
        }
    }
    fn paint(&mut self) {
        unsafe {
            let mut paint = PAINTSTRUCT::default();
            let dc = BeginPaint(self.hwnd, &mut paint);
            self.draw_background(dc);
            EndPaint(self.hwnd, &paint);
        }
    }
    fn draw_background(&mut self, dc: HDC) {
        unsafe {
            let mut rect = RECT::default();
            GetClientRect(self.hwnd, &mut rect);
            FillRect(dc, &rect, self.background);
            self.paints += 1;
            SetBkMode(dc, TRANSPARENT as i32);
            SetTextColor(dc, self.palette().text);
            SelectObject(dc, self.title_font);
            DrawIconEx(
                dc,
                self.scale(28),
                self.scale(28),
                self.icon,
                self.scale(40),
                self.scale(40),
                0,
                ptr::null_mut(),
                DI_NORMAL,
            );
            let mut title = RECT {
                left: self.scale(84),
                top: self.scale(22),
                right: rect.right - self.scale(196),
                bottom: self.scale(56),
            };
            let value = wide("Encrypted Vault");
            DrawTextW(
                dc,
                value.as_ptr(),
                -1,
                &mut title,
                DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            SelectObject(dc, self.small_font);
            SetTextColor(dc, self.palette().muted);
            let mut subtitle = RECT {
                left: self.scale(84),
                top: self.scale(58),
                right: rect.right - self.scale(28),
                bottom: self.scale(82),
            };
            let value = wide(self.t("tagline"));
            DrawTextW(
                dc,
                value.as_ptr(),
                -1,
                &mut subtitle,
                DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            let pen = CreatePen(PS_SOLID, 1, self.palette().line);
            let old = SelectObject(dc, pen);
            MoveToEx(dc, self.scale(28), self.scale(94), ptr::null_mut());
            LineTo(dc, rect.right - self.scale(28), self.scale(94));
            SelectObject(dc, old);
            DeleteObject(pen);
            if let Some(start) = self.animation {
                let fraction = (start.elapsed().as_secs_f32() / 0.18).min(1.0);
                let width = ((rect.right - self.scale(56)) as f32
                    * (1.0 - (1.0 - fraction).powi(3))) as i32;
                let brush = CreateSolidBrush(self.palette().accent);
                let bar = RECT {
                    left: self.scale(28),
                    top: self.scale(93),
                    right: self.scale(28) + width,
                    bottom: self.scale(96),
                };
                FillRect(dc, &bar, brush);
                DeleteObject(brush);
            }
        }
    }
    fn draw_item(&self, item: &DRAWITEMSTRUCT) {
        unsafe {
            let p = self.palette();
            let dc = item.hDC;
            let mut r = item.rcItem;
            if item.CtlID == LIST as u32 {
                let Some(vault) = self.snapshot.preferences.vaults.get(item.itemID as usize) else {
                    return;
                };
                let selected = item.itemState & ODS_SELECTED != 0;
                let brush = CreateSolidBrush(if selected { p.selected } else { p.surface });
                FillRect(dc, &r, brush);
                DeleteObject(brush);
                SetBkMode(dc, TRANSPARENT as i32);
                DrawIconEx(
                    dc,
                    r.left + self.scale(14),
                    r.top + self.scale(18),
                    self.small_icon,
                    self.scale(24),
                    self.scale(24),
                    0,
                    ptr::null_mut(),
                    DI_NORMAL,
                );
                let mut title = RECT {
                    left: r.left + self.scale(54),
                    top: r.top + self.scale(12),
                    right: r.right - self.scale(168),
                    bottom: r.top + self.scale(36),
                };
                SelectObject(dc, self.font);
                SetTextColor(dc, p.text);
                DrawTextW(
                    dc,
                    wide(&vault.alias).as_ptr(),
                    -1,
                    &mut title,
                    DT_SINGLELINE | DT_END_ELLIPSIS,
                );
                let state = if let Some(letter) = self.snapshot.mounted.get(&vault.path) {
                    format!("{} · {letter}:", self.t("unlocked"))
                } else {
                    self.t("locked").into()
                };
                let mut status = RECT {
                    left: r.right - self.scale(170),
                    top: r.top + self.scale(12),
                    right: r.right - self.scale(14),
                    bottom: r.top + self.scale(36),
                };
                SetTextColor(dc, if selected { p.text } else { p.muted });
                DrawTextW(
                    dc,
                    wide(&state).as_ptr(),
                    -1,
                    &mut status,
                    DT_SINGLELINE | DT_RIGHT | DT_END_ELLIPSIS,
                );
                let mut path = RECT {
                    left: r.left + self.scale(54),
                    top: r.top + self.scale(40),
                    right: r.right - self.scale(14),
                    bottom: r.bottom - self.scale(6),
                };
                SelectObject(dc, self.small_font);
                SetTextColor(dc, p.muted);
                DrawTextW(
                    dc,
                    wide(&vault.path.to_string_lossy()).as_ptr(),
                    -1,
                    &mut path,
                    DT_SINGLELINE | DT_PATH_ELLIPSIS,
                );
            } else {
                let primary = [PRIMARY, SUBMIT, DOWNLOAD].contains(&(item.CtlID as u16));
                let disabled = item.itemState & ODS_DISABLED != 0;
                let color = if disabled {
                    p.line
                } else if primary {
                    p.accent
                } else {
                    p.surface
                };
                let brush = CreateSolidBrush(color);
                let pen = CreatePen(PS_SOLID, 1, if primary { color } else { p.line });
                let old_brush = SelectObject(dc, brush);
                let old_pen = SelectObject(dc, pen);
                RoundRect(
                    dc,
                    r.left,
                    r.top,
                    r.right,
                    r.bottom,
                    self.scale(12),
                    self.scale(12),
                );
                SelectObject(dc, old_brush);
                SelectObject(dc, old_pen);
                DeleteObject(brush);
                DeleteObject(pen);
                let mut label = [0u16; 512];
                GetWindowTextW(item.hwndItem, label.as_mut_ptr(), label.len() as i32);
                SetBkMode(dc, TRANSPARENT as i32);
                SelectObject(dc, self.font);
                SetTextColor(
                    dc,
                    if disabled {
                        p.muted
                    } else if primary {
                        p.accent_text
                    } else {
                        p.text
                    },
                );
                r.left += self.scale(10);
                r.right -= self.scale(10);
                if item.itemState & ODS_SELECTED != 0 {
                    r.top += self.scale(1);
                }
                DrawTextW(
                    dc,
                    label.as_ptr(),
                    -1,
                    &mut r,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
                );
            }
            if item.itemState & ODS_FOCUS != 0 {
                InflateRect(&mut r, -self.scale(4), -self.scale(4));
                DrawFocusRect(dc, &r);
            }
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Every callback is panic-contained; owned store state lives on another thread.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        dispatch_window(hwnd, message, wparam, lparam)
    }))
    .unwrap_or(0);
    let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const UiCell;
    if let Some(cell) = unsafe { pointer.as_ref() } {
        // Modal native menus/dialogs can pump messages reentrantly. Defer one wake until the
        // outermost callback releases state; never spin by repeatedly reposting inside a dialog.
        if cell.state.try_borrow().is_ok() {
            if cell.pending_wake.replace(false) {
                unsafe {
                    PostMessageW(hwnd, WAKE, 0, 0);
                }
            }
            if cell.pending_restore.replace(false) {
                unsafe {
                    PostMessageW(hwnd, RESTORE, 0, 0);
                }
            }
        }
    }
    result
}
unsafe fn dispatch_window(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if message == EXIT {
        unsafe {
            DestroyWindow(hwnd);
        }
        return 0;
    }
    if message == WM_NCCREATE {
        let create = unsafe { &*(lparam as *const CREATESTRUCTW) };
        let state = create.lpCreateParams as *const UiCell;
        unsafe {
            (&*state).state.borrow_mut().hwnd = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize);
        }
    }
    let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const UiCell;
    if pointer.is_null() {
        return unsafe { DefWindowProcW(hwnd, message, wparam, lparam) };
    }
    let cell = unsafe { &*pointer };
    let Ok(mut guard) = cell.state.try_borrow_mut() else {
        if message == WAKE {
            cell.pending_wake.set(true);
        }
        if message == RESTORE {
            cell.pending_restore.set(true);
        }
        return unsafe { DefWindowProcW(hwnd, message, wparam, lparam) };
    };
    let ui = &mut *guard;
    if message == ui.taskbar_message && ui.taskbar_message != 0 {
        ui.tray_added = false;
        ui.update_tray();
        return 0;
    }
    match message {
        WM_CREATE => {
            ui.setup_resources();
            ui.build_controls();
            ui.update_tray();
            0
        }
        WM_COMMAND => {
            ui.command((wparam & 0xffff) as u16, ((wparam >> 16) & 0xffff) as u16);
            0
        }
        WAKE => {
            ui.drain();
            0
        }
        RESTORE => {
            ui.restore();
            0
        }
        TRAY => {
            match lparam as u32 {
                WM_LBUTTONUP => ui.restore(),
                WM_RBUTTONUP | WM_CONTEXTMENU => ui.tray_menu(),
                _ => (),
            }
            0
        }
        WM_CLOSE => {
            if ui.tray_added {
                unsafe {
                    KillTimer(hwnd, ANIMATION);
                    ShowWindow(hwnd, SW_HIDE);
                }
                ui.animation = None;
                ui.clear_secrets();
                ui.dirty = true;
            } else {
                ui.dispatch(Command::Quit, false);
            }
            0
        }
        WM_SIZE => {
            if wparam == SIZE_MINIMIZED as usize {
                unsafe {
                    KillTimer(hwnd, ANIMATION);
                }
                ui.animation = None;
            } else if ui.visible() {
                ui.layout();
            }
            0
        }
        WM_SHOWWINDOW => {
            if wparam == 0 {
                unsafe {
                    KillTimer(hwnd, ANIMATION);
                }
                ui.animation = None;
            }
            0
        }
        WM_DPICHANGED => {
            let rect = unsafe { &*(lparam as *const RECT) };
            unsafe {
                SetWindowPos(
                    hwnd,
                    ptr::null_mut(),
                    rect.left,
                    rect.top,
                    rect.right - rect.left,
                    rect.bottom - rect.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
            ui.setup_resources();
            if ui.visible() {
                ui.build_controls();
            } else {
                ui.dirty = true;
            }
            0
        }
        WM_GETMINMAXINFO => {
            let info = unsafe { &mut *(lparam as *mut MINMAXINFO) };
            info.ptMinTrackSize = POINT {
                x: ui.scale(680),
                y: ui.scale(760),
            };
            0
        }
        WM_TIMER if wparam == ANIMATION => {
            if !ui.visible()
                || ui
                    .animation
                    .is_none_or(|s| s.elapsed() >= Duration::from_millis(180))
            {
                unsafe {
                    KillTimer(hwnd, ANIMATION);
                }
                ui.animation = None;
            }
            if ui.visible() {
                let (cw, _) = ui.logical_size();
                let rect = RECT {
                    left: ui.scale(28),
                    top: ui.scale(92),
                    right: ui.scale(cw - 28),
                    bottom: ui.scale(98),
                };
                unsafe {
                    InvalidateRect(hwnd, &rect, 0);
                }
            }
            0
        }
        WM_PAINT => {
            if ui.visible() {
                ui.paint();
            } else {
                unsafe {
                    ValidateRect(hwnd, ptr::null());
                }
            }
            0
        }
        WM_PRINTCLIENT => {
            ui.draw_background(wparam as HDC);
            0
        }
        WM_ERASEBKGND => 1,
        WM_DRAWITEM => {
            if ui.visible() {
                ui.draw_item(unsafe { &*(lparam as *const DRAWITEMSTRUCT) });
            }
            1
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let dc = wparam as HDC;
            let p = ui.palette();
            let error =
                unsafe { GetDlgCtrlID(lparam as HWND) } == MESSAGE as i32 && ui.message_error;
            unsafe {
                SetTextColor(dc, if error { p.error } else { p.text });
                SetBkColor(dc, p.background);
                SetBkMode(dc, TRANSPARENT as i32);
            }
            ui.background as isize
        }
        WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => {
            let dc = wparam as HDC;
            let p = ui.palette();
            unsafe {
                SetTextColor(dc, p.text);
                SetBkColor(dc, p.surface);
            }
            ui.surface as isize
        }
        WM_DESTROY => {
            ui.clear_secrets();
            unsafe {
                KillTimer(hwnd, ANIMATION);
                if ui.tray_added {
                    let mut data: NOTIFYICONDATAW = std::mem::zeroed();
                    data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                    data.hWnd = hwnd;
                    data.uID = 1;
                    Shell_NotifyIconW(NIM_DELETE, &data);
                }
                PostQuitMessage(0);
            }
            0
        }
        WM_NCDESTROY => unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DefWindowProcW(hwnd, message, wparam, lparam)
        },
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

pub fn run() -> Result<()> {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED as u32);
    }
    let settings = preferences::config_path()?;
    let (preferences, initial_message, initial_error) = match Preferences::load(&settings) {
        Ok(p) => (
            p,
            if dokan::runtime_present() {
                "security_note"
            } else {
                "runtime_missing"
            },
            false,
        ),
        Err(_) => (
            Preferences {
                startup_updates: false,
                ..Preferences::default()
            },
            "error_preferences",
            true,
        ),
    };
    let mutex_name = wide("Local\\EncryptedVault.Main.0.1");
    let mutex = unsafe { CreateMutexW(ptr::null(), 0, mutex_name.as_ptr()) };
    if mutex.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        let existing = unsafe { FindWindowW(class_name().as_ptr(), ptr::null()) };
        if !existing.is_null() {
            unsafe {
                let mut process_id = 0;
                GetWindowThreadProcessId(existing, &mut process_id);
                AllowSetForegroundWindow(process_id);
                PostMessageW(existing, RESTORE, 0, 0);
            }
        }
        unsafe {
            CloseHandle(mutex);
            CoUninitialize();
        }
        return Ok(());
    }
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    // MAKEINTRESOURCEW(1): an integer resource identifier, never a memory address.
    #[allow(clippy::manual_dangling_ptr)]
    let resource = 1usize as *const u16;
    let icon =
        unsafe { LoadImageW(instance, resource, IMAGE_ICON, 48, 48, LR_DEFAULTCOLOR) } as HICON;
    let small_icon =
        unsafe { LoadImageW(instance, resource, IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR) } as HICON;
    let class = class_name();
    let window_class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hIcon: icon,
        hCursor: unsafe { LoadCursorW(ptr::null_mut(), IDC_ARROW) },
        lpszClassName: class.as_ptr(),
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { RegisterClassW(&window_class) } == 0 {
        unsafe {
            CloseHandle(mutex);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    let mut system_motion = 1i32;
    unsafe {
        SystemParametersInfoW(
            SPI_GETCLIENTAREAANIMATION,
            0,
            &mut system_motion as *mut _ as _,
            0,
        );
    }
    let ui = Box::new(UiCell {
        state: RefCell::new(Ui {
            hwnd: ptr::null_mut(),
            icon,
            small_icon,
            font: ptr::null_mut(),
            title_font: ptr::null_mut(),
            small_font: ptr::null_mut(),
            background: ptr::null_mut(),
            surface: ptr::null_mut(),
            controls: BTreeMap::new(),
            next_label: 1000,
            snapshot: Snapshot {
                preferences,
                mounted: BTreeMap::new(),
            },
            backend: None,
            page: Page::Home,
            selected: 0,
            path: String::new(),
            message: initial_message,
            message_error: initial_error,
            busy: false,
            dirty: false,
            return_home: false,
            update: UpdateView::Idle,
            tray_added: false,
            tray_tip: String::new(),
            taskbar_message: unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) },
            animation: None,
            system_motion: system_motion != 0,
            paints: 0,
            capture_mode: false,
        }),
        pending_wake: Cell::new(false),
        pending_restore: Cell::new(false),
    });
    let dpi = unsafe { GetDpiForSystem() }.max(96);
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: (680 * dpi / 96) as i32,
        bottom: (720 * dpi / 96) as i32,
    };
    unsafe {
        AdjustWindowRectExForDpi(&mut rect, WS_OVERLAPPEDWINDOW, 0, 0, dpi);
    }
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class.as_ptr(),
            wide("Encrypted Vault").as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            rect.right - rect.left,
            rect.bottom - rect.top,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            &*ui as *const UiCell as *const c_void,
        )
    };
    if hwnd.is_null() {
        unsafe {
            CloseHandle(mutex);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    let wake_hwnd = hwnd as usize;
    {
        let mut state = ui.state.borrow_mut();
        state.backend = Some(Backend::start(
            state.snapshot.preferences.clone(),
            settings,
            move || unsafe {
                PostMessageW(wake_hwnd as HWND, WAKE, 0, 0);
            },
        ));
    }
    unsafe {
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL as usize, small_icon as isize);
        SendMessageW(hwnd, WM_SETICON, ICON_BIG as usize, icon as isize);
        ShowWindow(hwnd, SW_SHOW);
    }
    {
        let mut state = ui.state.borrow_mut();
        if updates::startup_check_enabled(&state.snapshot.preferences) {
            state.update = UpdateView::Checking;
            if let Some(backend) = &state.backend {
                backend.check_updates(true);
            }
        }
    }
    let mut message = MSG::default();
    loop {
        let result = unsafe { GetMessageW(&mut message, ptr::null_mut(), 0, 0) };
        if result <= 0 {
            break;
        }
        if unsafe { IsDialogMessageW(hwnd, &message) } == 0 {
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    let state = ui.state.borrow();
    unsafe {
        for font in [state.font, state.title_font, state.small_font] {
            DeleteObject(font);
        }
        for brush in [state.background, state.surface] {
            DeleteObject(brush);
        }
        DestroyIcon(icon);
        DestroyIcon(small_icon);
        CloseHandle(mutex);
        CoUninitialize();
    }
    Ok(())
}

/// Isolated, hidden-window render-save-exit mode. It never starts a controller, tray, network,
/// filesystem runtime or settings session. Requires a Windows desktop for native control printing.
pub fn screenshot(args: &[std::ffi::OsString]) -> Result<()> {
    use crate::{error::VaultError, preferences::RecentVault};
    if args.len() != 6 {
        return Err(VaultError::InvalidPath);
    }
    let output = PathBuf::from(&args[2]);
    if !output.is_absolute() || output.exists() {
        return Err(VaultError::InvalidPath);
    }
    let screen = args[3].to_str().ok_or(VaultError::InvalidPath)?;
    let page = match screen {
        "home" | "empty" => Page::Home,
        "settings" => Page::Settings,
        "create" => Page::Add(true),
        "unlock" => Page::Unlock(0),
        _ => return Err(VaultError::InvalidPath),
    };
    let locale = args[4].to_str().ok_or(VaultError::InvalidPath)?;
    let language = Language::ALL
        .into_iter()
        .find(|l| l.code() == locale)
        .ok_or(VaultError::InvalidPath)?;
    let theme = match args[5].to_str() {
        Some("light") => Theme::Light,
        Some("dark") => Theme::Dark,
        _ => return Err(VaultError::InvalidPath),
    };
    // Only capture-owned process exits on a deadline. Main returns immediately on success.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(8));
        std::process::exit(3);
    });
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED as u32);
    }
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    #[allow(clippy::manual_dangling_ptr)]
    let resource = 1usize as *const u16;
    let icon =
        unsafe { LoadImageW(instance, resource, IMAGE_ICON, 48, 48, LR_DEFAULTCOLOR) } as HICON;
    let small_icon =
        unsafe { LoadImageW(instance, resource, IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR) } as HICON;
    if icon.is_null() || small_icon.is_null() {
        return Err(VaultError::Io(std::io::Error::last_os_error()));
    }
    let class = wide("EncryptedVault.IsolatedCapture");
    let wc = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hIcon: icon,
        lpszClassName: class.as_ptr(),
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { RegisterClassW(&wc) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut p = Preferences {
        language,
        theme,
        reduced_motion: true,
        startup_updates: false,
        ..Default::default()
    };
    if screen != "empty" {
        p.vaults.push(RecentVault {
            alias: "Personal".into(),
            path: PathBuf::from("C:\\Vault fixtures\\Personal"),
        });
        p.vaults.push(RecentVault {
            alias: "Archive".into(),
            path: PathBuf::from("C:\\Vault fixtures\\Archive"),
        });
    }
    let ui = Box::new(UiCell {
        state: RefCell::new(Ui {
            hwnd: ptr::null_mut(),
            icon,
            small_icon,
            font: ptr::null_mut(),
            title_font: ptr::null_mut(),
            small_font: ptr::null_mut(),
            background: ptr::null_mut(),
            surface: ptr::null_mut(),
            controls: BTreeMap::new(),
            next_label: 1000,
            snapshot: Snapshot {
                preferences: p,
                mounted: BTreeMap::new(),
            },
            backend: None,
            page,
            selected: 0,
            path: "C:\\Vault fixtures\\New vault".into(),
            message: "security_note",
            message_error: false,
            busy: false,
            dirty: false,
            return_home: false,
            update: UpdateView::Idle,
            tray_added: false,
            tray_tip: String::new(),
            taskbar_message: 0,
            animation: None,
            system_motion: false,
            paints: 0,
            capture_mode: true,
        }),
        pending_wake: Cell::new(false),
        pending_restore: Cell::new(false),
    });
    let dpi = unsafe { GetDpiForSystem() }.max(96);
    let width = (680 * dpi / 96) as i32;
    let height = (720 * dpi / 96) as i32;
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            wide("Encrypted Vault capture").as_ptr(),
            WS_POPUP | WS_CLIPCHILDREN,
            0,
            0,
            width,
            height,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            &*ui as *const UiCell as _,
        )
    };
    if hwnd.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = capture_client(&ui, hwnd, &output);
    unsafe {
        DestroyWindow(hwnd);
    }
    {
        let state = ui.state.borrow();
        unsafe {
            for font in [state.font, state.title_font, state.small_font] {
                DeleteObject(font);
            }
            for brush in [state.background, state.surface] {
                DeleteObject(brush);
            }
            DestroyIcon(icon);
            DestroyIcon(small_icon);
            CoUninitialize();
        }
    }
    result
}

fn capture_client(ui: &UiCell, hwnd: HWND, path: &std::path::Path) -> Result<()> {
    use crate::error::VaultError;
    unsafe {
        let mut rect = RECT::default();
        GetClientRect(hwnd, &mut rect);
        let width = rect.right;
        let height = rect.bottom;
        if width <= 0 || height <= 0 || width > 4096 || height > 4096 {
            return Err(VaultError::TooLarge);
        }
        let reference = GetDC(hwnd);
        let dc = CreateCompatibleDC(reference);
        ReleaseDC(hwnd, reference);
        let mut info: BITMAPINFO = std::mem::zeroed();
        info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        info.bmiHeader.biWidth = width;
        info.bmiHeader.biHeight = -height;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        let mut pixels = ptr::null_mut();
        let bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut pixels, ptr::null_mut(), 0);
        if dc.is_null() || bitmap.is_null() || pixels.is_null() {
            if !dc.is_null() {
                DeleteDC(dc);
            }
            return Err(std::io::Error::last_os_error().into());
        }
        let old = SelectObject(dc, bitmap);
        SendMessageW(hwnd, WM_PRINTCLIENT, dc as usize, PRF_CLIENT as isize);
        let controls: Vec<_> = ui
            .state
            .borrow()
            .controls
            .values()
            .map(|c| c.hwnd)
            .collect();
        for control in controls {
            let mut bounds = RECT::default();
            GetWindowRect(control, &mut bounds);
            let mut origin = POINT {
                x: bounds.left,
                y: bounds.top,
            };
            ScreenToClient(hwnd, &mut origin);
            let mut previous = POINT::default();
            SetViewportOrgEx(dc, origin.x, origin.y, &mut previous);
            SendMessageW(
                control,
                WM_PRINT,
                dc as usize,
                (PRF_CLIENT | PRF_CHILDREN | PRF_ERASEBKGND) as isize,
            );
            SetViewportOrgEx(dc, previous.x, previous.y, ptr::null_mut());
        }
        GdiFlush();
        let bytes =
            std::slice::from_raw_parts(pixels as *const u8, width as usize * height as usize * 4);
        let mut rgba = bytes.to_vec();
        for pixel in rgba.as_chunks_mut::<4>().0 {
            pixel.swap(0, 2);
            pixel[3] = 255;
        }
        SelectObject(dc, old);
        DeleteObject(bitmap);
        DeleteDC(dc);
        crate::capture::save_png(path, width as u32, height as u32, &rgba)
    }
}
