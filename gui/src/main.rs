#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
#![allow(rustdoc::missing_crate_level_docs)] // it's an example

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use directories::ProjectDirs;
use eframe::egui;
use eframe::epaint::text;
use egui::{IconData, TextEdit, TextStyle};
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use shared::{load_private_key, load_certificate, PrivateKey, Certificate, CertificateMatches, Challenge, Binary, AnswerEngine, PrivateKeyAndCertificate};

const CONFIG_NAME: &str = "settings.toml";


fn load_icon() -> IconData {
    let png_bytes = include_bytes!("../../assets/Authenticator.ico");

    let image = image::load_from_memory(png_bytes)
        .unwrap()
        .into_rgba8();
    let (width, height) = image.dimensions();
    let rgba = image.into_vec();

    IconData {
        rgba,
        width: width as _,
        height: height as _,
    }
}


#[derive(Deserialize, Serialize)]
struct Config {
    private_key_path: Option<PathBuf>,
    certificate_path: Option<PathBuf>,
}

impl Config {
    fn path() -> PathBuf {
        let proj_dirs = ProjectDirs::from("com", "lauberware", "authenticator").expect("Could not determine project directories");
        let folder = proj_dirs.config_dir();
        let _ = fs::create_dir_all(folder);
        folder.join(CONFIG_NAME)
    }

    fn new() -> Self {
        Config{private_key_path: None, certificate_path: None}
    }

    fn load() -> Self {
        // only load the data but do not validate them yet
        if let Ok(content) = fs::read_to_string(&Config::path()){
            let config_res: Result<Config, _> = toml::from_str(&content);
            if let Ok(config) = config_res{
                config
            } else {
                Config{private_key_path: None, certificate_path: None}
            }
        } else {
            Config{private_key_path: None, certificate_path: None}

        }
    }

    fn save(&self) {
        log::info!("Saving config to {}", Config::path().display());
        if let Ok(toml_str) = toml::to_string_pretty(&self){
            match fs::write(&Config::path(), toml_str) {
                Ok(_) => {},
                Err(e) => {log::error!("Could not save config to disk: {}", e);}
            }
        }
    }

}

fn main() -> eframe::Result {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([620.0, 540.0])
            .with_icon(Arc::new(load_icon())),
        ..Default::default()
    };

    eframe::run_native(
        "Authenticator",
        options,
        Box::new(|_cc| {
            // This gives us image support:
            //gui_extras::install_image_loaders(&cc.egui_ctx);
            Ok(Box::<AppState>::default())
        }),
    )
}

struct AppState {
    challenge: String,
    answer: String,
    private_key: Option<PrivateKey>,
    certificate: Option<Certificate>,
    config: Config,
    answer_engine: Option<Box<dyn AnswerEngine>>
}

impl Default for AppState {
    fn default() -> Self {
        let config = Config::load();
        let mut res = Self {
            challenge: "".to_owned(),
            answer: String::new(),
            private_key: None,
            certificate: None,
            config: Config::new(),
            answer_engine: None
        };

        if let Some(private_key_path) = config.private_key_path {
            let _ = res.set_private_key(private_key_path);
        }

        if let Some(certificate_path) = config.certificate_path {
            let _ = res.set_certificate(certificate_path);
        }

        res.config.save();
        res
    }
}

impl AppState {

    fn reset_private(&mut self){
        self.reset_certificate();
        self.private_key = None;
        self.config.private_key_path = None;
        self.config.save();
    }

    fn reset_certificate(&mut self){
        self.answer_engine = None;
        self.certificate = None;
        self.config.certificate_path = None;
        self.config.save();
    }

    fn set_private_key(&mut self, private_key_path: PathBuf) -> Result<(), String>{
        let private = load_private_key(&private_key_path)?;
        
        if let Some(certificate) = self.certificate.as_ref(){
            if let Err(_) = private.matches(certificate){
                self.reset_certificate();
            }
        }
        self.private_key = Some(private);
        self.config.private_key_path = Some(private_key_path);
        self.config.save();
        Ok(())
    }

    fn set_certificate(&mut self, certificate_path: PathBuf) -> Result<(), String>{
        let private = self.private_key.as_ref().ok_or("Cannot set public keys if no private keys is set".to_owned())?;
        let certificate = load_certificate(&certificate_path)?;

        if let Err(e) = private.matches(&certificate){
            return Err(format!("Public keys not compatible with set private keys: {}", e));
        }

        let answer_engine = PrivateKeyAndCertificate::new(private.clone(), certificate.clone()).map_err(|e| format!("Could not generate answer engine: {}", e))?;

        self.answer_engine = Some(Box::new(answer_engine));
        self.certificate = Some(certificate);
        self.config.certificate_path = Some(certificate_path);
        self.config.save();
        Ok(())
    }

    pub fn ui_private_key(&mut self, ui: &mut egui::Ui, file_picker: &mut dyn FnMut()->Option<PathBuf>) {
        ui.horizontal(|ui| {
            let button_label = match &self.config.private_key_path {
                Some(t) => format!("Private keys: {}", t.display()),
                _ => "Select private keys".to_owned(),
            };
            let button = ui.button(button_label);
            if button.clicked() {
                if let Some(path) = file_picker() {
                    if let Err(msg) = self.set_private_key(path) {
                        self.answer = msg;
                    }
                }
            }

            if button.secondary_clicked() {
                self.reset_certificate();
                self.reset_private();
                self.answer = "".to_owned()
            }

        });
    }

    pub fn ui_certificate(&mut self, ui: &mut egui::Ui, file_picker: &mut dyn FnMut()->Option<PathBuf>) {
        ui.add_enabled(self.private_key.is_some(), |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                let button_label = match &self.config.certificate_path {
                    Some(t) => format!("Signed public keys: {}", t.display()),
                    _ => "Select CA signed public keys".to_owned(),
                };
                let button = ui.button(button_label);
                if button.clicked() {
                    if let Some(path) = file_picker() {
                        if let Err(msg) = self.set_certificate(path) {
                            self.answer = msg;
                        } else {
                            self.answer = "".to_owned();
                        }
                    }
                }
                if button.secondary_clicked() {
                    self.reset_certificate();
                    self.answer = "".to_owned();
                }
                button
            }).inner
        });
    }

    pub fn ui_answer_generator(&mut self, ui: &mut egui::Ui, clipboard: &mut dyn FnMut(String)) {
        ui.add_enabled(self.answer_engine.is_some(), |ui: &mut egui::Ui| {
            ui.heading("Challenge:");
            ui.add_sized([ui.available_width(), 0.0], TextEdit::singleline(&mut self.challenge));
            ui.horizontal(|ui| {
                let button = ui.button("Generate");
                if button.clicked() {
                    match Binary::try_from(&self.challenge){
                        Ok(binary) => {
                            match Challenge::try_from(binary) {
                                Ok(challenge) => {
                                    let engine = self.answer_engine.as_ref().unwrap();
                                    match engine.generate_answer(&challenge){
                                        Ok(answer) => {
                                            let tmp = answer.to_string();
                                            clipboard(tmp.clone());
                                            self.answer = tmp;
                                        },
                                        Err(e) => {self.answer = e.to_string()}
                                    }
                                },
                                Err(_) => {
                                    self.answer = "No challenge found".to_owned();
                                }
                            }
                        }
                        Err(_) => {
                            self.answer = "No challenge found".to_owned();
                        }
                    }
                }
                let button2 = ui.button("Copy to clipboard");
                if button2.clicked() {
                    clipboard(self.answer.clone());
                }
                button
            }).inner
        });
    }

    pub fn ui_display(&mut self, ui: &mut egui::Ui) {
        let mut job = text::LayoutJob::simple(
            self.answer.clone(),
            TextStyle::Monospace.resolve(ui.style()),
            ui.visuals().text_color(),
            f32::INFINITY,
        );

        job.wrap = text::TextWrapping {      // force wrapping at fixed width instead of punctuation
            max_width: ui.available_width(), // pixels, not characters
            break_anywhere: true,            // break anywhere, not just at spaces
            ..Default::default()
        };
        ui.label(job);
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            AppState::ui_private_key(self, ui, &mut || FileDialog::new().pick_file());
            AppState::ui_certificate(self, ui, &mut || FileDialog::new().pick_file());
            AppState::ui_answer_generator(self, ui, &mut |text| ctx.copy_text(text));
            AppState::ui_display(self, ui);
        });
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::str::FromStr;
    use egui::accesskit;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;
    use super::*;

    #[test]
    fn test_cert_load_workflow() {
        let mut app = AppState::default();
        let private_key_path = PathBuf::from_str("../tests/signed").unwrap();
        let certificate_path = PathBuf::from_str("../tests/signed-cert.pub").unwrap();
        app.set_private_key(private_key_path).unwrap();
        app.set_certificate(certificate_path).unwrap();
        assert!(app.private_key.is_some());
        assert!(app.certificate.is_some());
        assert!(app.answer_engine.is_some());
    }

    #[test]
    fn test_load_icon(){
        let _= load_icon();
    }

    #[test]
    fn test_main_window() {
        let app = Rc::new(RefCell::new(AppState::default()));
        //mocks
        let mut private_key_picker = || PathBuf::from_str("../tests/signed").ok();
        let mut certificate_picker = || PathBuf::from_str("../tests/signed-cert.pub").ok();

        let clipboard_called = Rc::new(RefCell::new(false));
        let clipboard_clone = clipboard_called.clone();

        let mut fake_clipboard = move |_: String| {
            *clipboard_called.borrow_mut() = true;        };

        let mut harness = Harness::new(|ctx: &egui::Context| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let mut app = app.borrow_mut();
                app.ui_private_key(ui, &mut private_key_picker);
                app.ui_certificate(ui, &mut certificate_picker);
                app.ui_answer_generator(ui, &mut fake_clipboard);
                app.ui_display(ui);
            });
        });

        // Click the "Select private keys" button
        {
            // not a typo the label is either Select private keys or Private Key: something so this matches both
            let btn = harness.get_by_label_contains("rivate keys");
            btn.click();
        }
        harness.run();
        assert!(app.borrow().private_key.is_some());
        assert_eq!(app.borrow().config.private_key_path.as_ref().unwrap(), &PathBuf::from_str("../tests/signed").unwrap());
        {
            let btn = harness.get_by_label_contains("public keys");
            btn.click();
            let btn = harness.get_by_label("Copy to clipboard");
            btn.click();
        }
        harness.run();
        assert!(*clipboard_clone.borrow());
        assert!(app.borrow().certificate.is_some());
        assert_eq!(app.borrow().config.certificate_path.as_ref().unwrap(), &PathBuf::from_str("../tests/signed-cert.pub").unwrap());
        {
            let challenge_str = "[[[dUHu!9csD2^MlD3Yf_|-sUU}Ut8s25A5Ry6j}}w%]]]";
            let txt = harness.get_by(|node| {node.role() == accesskit::Role::TextInput});
            txt.focus();
            txt.type_text(challenge_str);
        }
        harness.run();
        {
            let btn = harness.get_by_label("Generate");
            btn.click();
        }
        harness.run();
        {
            let answer_str = "[[[0R:7rC9mWd0t=nRuOOl+>8Swx;;KzD9Sn;qvo$SHmrfapZ<)#)2adM!D3-6AGV**_!-!hoP63$Ntf2940{s:0000Wb8~1dWn?lnH8D9YV`Xx5Ep{+5KyPqmZgX>JE@N+P0000W@6eqn1dj9(Z0ZI-kiyUZ!YHR*k)zAYKgNv`W=8ME0000WAl)rJ)FEJ|d@Zy`jdI?<;)*c^slX9E!17Y>aB$}`0000000000000010000KbY*jNb#rBMKxKGgZE$R5E@N+P0000C00008bY*jNb#rBM00000X#&1500000d%=>W000000001j0000LaAk6BX>=`EF)=M>Z*q5Ga%5?4X8-^I000007jR{AZE18ZVP|D-bS-9Ya(7{JWNB_^000000000MaAk6BX>=`cZ*p`kW^ZzLVRB??Zf5`h00000019wra&2jJEpT*s000000000EaAk6BX>=`hb7gWZa$^7h000000000005bpp01I<-Xf0)AGBq_ZIRF3vAZhB==tO2#AUh_rMLGzKsz6=J#5NtAYAqde990lr-2eapQvd(}3v+X5EoEdfH8n9g0000$74Z7x9c{A9ozu0KKI&lKppMRYt|S_7K}UQ0Bf?aw-06hRfox*&=H!Czutqff40`KrycD3oZ>j(&bdhuo]]]";
            let out = harness.get_by(|node| { node.role() == accesskit::Role::Label && node.value().unwrap() != "Challenge:"});
            let output = out.value().unwrap();
            assert_eq!(output, answer_str);
        }
        harness.run();
        {
            let btn = harness.get_by_label_contains("Private keys");
            btn.click_secondary();
        }
        harness.run();
        assert!(app.borrow().private_key.is_none());
        assert!(app.borrow().certificate.is_none());
        assert!(app.borrow().config.private_key_path.is_none());
        assert!(app.borrow().config.certificate_path.is_none());
    }
}


