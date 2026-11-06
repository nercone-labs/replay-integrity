use serde::{Deserialize, Serialize};

/// How TEESimulator-RS handles the keys of a package (`target.txt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TargetMode {
    /// No suffix: the certificates of the device's own keystore are patched when it works,
    /// and keys are generated otherwise.
    Auto,
    /// Suffix `!`: keys are always generated and attested with the keybox.
    Generate,
    /// Suffix `?`: the device's certificates are always patched.
    Patch,
}

impl TargetMode {
    pub fn suffix(&self) -> &'static str {
        match self {
            TargetMode::Auto => "",
            TargetMode::Generate => "!",
            TargetMode::Patch => "?",
        }
    }
}

/// One package in the list, and how its keys are handled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub package: String,
    pub mode: TargetMode,
}

impl Target {
    /// Whether `name` is a package name as the package manager accepts it: two or more
    /// segments separated by `.`, each a letter followed by letters, digits and `_`.
    pub fn is_package_name(name: &str) -> bool {
        let mut segments = 0;
        for segment in name.split('.') {
            let mut characters = segment.chars();
            if !characters.next().is_some_and(|first| first.is_ascii_alphabetic()) {
                return false;
            }
            if !characters.all(|character| character.is_ascii_alphanumeric() || character == '_') {
                return false;
            }
            segments += 1;
        }
        segments >= 2
    }
}

/// The list of packages whose keys TEESimulator-RS attests (`target.txt`), without the keybox
/// sections of the TrickyStore format, which this engine does not use.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TargetList {
    pub targets: Vec<Target>,
}

impl TargetList {
    /// Google Play services (which attests through DroidGuard), Google Services Framework
    /// (which shares its UID) and the Play Store. They always need attestation, so they are
    /// always in the list.
    pub const ALWAYS: [&'static str; 3] = ["com.google.android.gms", "com.google.android.gsf", "com.android.vending"];

    /// Device makers' wallet and payment applications, which need attestation when installed.
    pub const WALLET: [&'static str; 6] = [
        "com.google.android.apps.walletnfcrel",
        "com.google.android.apps.nbu.paisa.user",
        "com.samsung.android.spay",
        "com.samsung.android.samsungpay.gear",
        "com.huawei.wallet",
        "com.oplus.wallet",
    ];

    /// Managers of Xposed, whose hooking a process breaks its STRONG verdict, so they are kept
    /// out of the list.
    pub const EXPOSED: [&'static str; 4] =
        ["org.lsposed.manager", "io.github.lsposed.manager", "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager"];

    /// Builds the list from the installed packages and the settings. The Play stack comes
    /// first and is always in the list; then the third-party packages, the installed wallet
    /// applications (which are often system packages) and the extra packages, without the
    /// excluded ones and without Xposed managers. Every target gets the mode of the settings.
    pub fn build(installed: &[String], third_party: &[String], settings: &crate::Settings) -> TargetList {
        let mut targets = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mode = settings.target_mode;
        for package in TargetList::ALWAYS {
            if seen.insert(package) {
                targets.push(Target { package: package.to_string(), mode });
            }
        }
        let wallets = TargetList::WALLET.iter().filter(|wallet| installed.iter().any(|package| package == *wallet));
        let candidates = third_party.iter().map(String::as_str).chain(wallets.copied()).chain(settings.extra_packages.iter().map(String::as_str));
        for package in candidates {
            let excluded = TargetList::EXPOSED.contains(&package) || settings.excluded_packages.iter().any(|excluded| excluded == package);
            if !excluded && Target::is_package_name(package) && seen.insert(package) {
                targets.push(Target { package: package.to_string(), mode });
            }
        }
        TargetList { targets }
    }

    /// The file as `target.txt`: one package per line, with the suffix of its mode.
    pub fn render(&self) -> String {
        let mut text = String::new();
        for target in &self.targets {
            text.push_str(&target.package);
            text.push_str(target.mode.suffix());
            text.push('\n');
        }
        text
    }

    /// Parses a `target.txt`, keeping package lines and dropping keybox sections (`[name.xml]`)
    /// and comments. A package listed twice keeps its first line.
    pub fn parse(text: &str) -> TargetList {
        let mut targets: Vec<Target> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || (line.starts_with('[') && line.ends_with(']')) {
                continue;
            }
            let (package, mode) = if let Some(package) = line.strip_suffix('!') {
                (package.trim(), TargetMode::Generate)
            } else if let Some(package) = line.strip_suffix('?') {
                (package.trim(), TargetMode::Patch)
            } else {
                (line, TargetMode::Auto)
            };
            if !package.is_empty() && !targets.iter().any(|target| target.package == package) {
                targets.push(Target { package: package.to_string(), mode });
            }
        }
        TargetList { targets }
    }

    pub fn packages(&self) -> impl Iterator<Item = &str> {
        self.targets.iter().map(|target| target.package.as_str())
    }
}
