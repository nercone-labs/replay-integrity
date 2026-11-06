use serde::Serialize;

/// How TEESimulator-RS handles the keys of a package (`target.txt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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

    /// Builds the list from the installed third-party packages and extra packages the user
    /// added. The always-attested packages come first; Xposed managers are left out.
    pub fn build(third_party: &[String], extra: &[String]) -> TargetList {
        let mut targets = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut add = |package: &str, mode: TargetMode, targets: &mut Vec<Target>| {
            if !TargetList::EXPOSED.contains(&package) && seen.insert(package.to_string()) {
                targets.push(Target { package: package.to_string(), mode });
            }
        };
        for package in TargetList::ALWAYS {
            add(package, TargetMode::Auto, &mut targets);
        }
        for package in third_party.iter().chain(extra.iter()) {
            if TargetList::ALWAYS.contains(&package.as_str()) {
                continue;
            }
            add(package, TargetMode::Auto, &mut targets);
        }
        for package in TargetList::WALLET {
            if third_party.iter().any(|installed| installed == package) {
                add(package, TargetMode::Auto, &mut targets);
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
    /// and comments.
    pub fn parse(text: &str) -> TargetList {
        let mut targets = Vec::new();
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
            if !package.is_empty() {
                targets.push(Target { package: package.to_string(), mode });
            }
        }
        TargetList { targets }
    }

    pub fn packages(&self) -> impl Iterator<Item = &str> {
        self.targets.iter().map(|target| target.package.as_str())
    }
}
