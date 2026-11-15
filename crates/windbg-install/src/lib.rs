use anyhow::{bail, ensure, Context};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use zip::ZipArchive;

pub const DEFAULT_APPINSTALLER_URL: &str = "https://aka.ms/windbg/download";

#[derive(Debug, Clone)]
pub struct WindbgManager {
    install_dir: PathBuf,
    appinstaller_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WindbgStatus {
    pub install_dir: PathBuf,
    pub installed: bool,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub update_available: Option<bool>,
    pub dbgx_path: Option<PathBuf>,
    pub appinstaller_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallResult {
    pub install_dir: PathBuf,
    pub version: String,
    pub dbgx_path: PathBuf,
    pub installed: bool,
    pub updated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInstallerInfo {
    pub version: String,
    pub bundle_uri: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X64,
    X86,
    Arm64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundlePackage {
    pub file_name: String,
    pub architecture: String,
}

impl WindbgManager {
    pub fn new(install_dir: Option<PathBuf>) -> anyhow::Result<Self> {
        Ok(Self {
            install_dir: install_dir.unwrap_or(default_install_dir()?),
            appinstaller_url: DEFAULT_APPINSTALLER_URL.to_string(),
        })
    }

    pub fn with_appinstaller_url(
        install_dir: Option<PathBuf>,
        appinstaller_url: impl Into<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            install_dir: install_dir.unwrap_or(default_install_dir()?),
            appinstaller_url: appinstaller_url.into(),
        })
    }

    pub fn status(&self, check_latest: bool) -> anyhow::Result<WindbgStatus> {
        let installed_version = self.installed_version()?;
        let dbgx_path = installed_version
            .as_ref()
            .and_then(|version| self.version_dir(version).ok())
            .map(|dir| dir.join("DbgX.Shell.exe"))
            .filter(|path| path.is_file());
        let latest_version = if check_latest {
            Some(self.fetch_appinstaller()?.version)
        } else {
            None
        };
        let update_available = match (&installed_version, &latest_version) {
            // A recorded version whose DbgX.Shell.exe is missing is reinstalled by `update`.
            (Some(installed), Some(latest)) => Some(installed != latest || dbgx_path.is_none()),
            (None, Some(_)) => Some(true),
            _ => None,
        };

        Ok(WindbgStatus {
            install_dir: self.install_dir.clone(),
            installed: dbgx_path.is_some(),
            installed_version,
            latest_version,
            update_available,
            dbgx_path,
            appinstaller_url: self.appinstaller_url.clone(),
        })
    }

    pub fn install(&self, force: bool) -> anyhow::Result<InstallResult> {
        fs::create_dir_all(&self.install_dir)
            .with_context(|| format!("creating {}", self.install_dir.display()))?;
        let _lock = InstallLock::acquire(&self.install_dir)?;

        let previous_version = self.installed_version()?;
        let appinstaller = self.fetch_appinstaller()?;
        let version_dir = self.version_dir(&appinstaller.version)?;
        let dbgx_path = version_dir.join("DbgX.Shell.exe");
        if !force && dbgx_path.is_file() {
            self.write_installed_version(&appinstaller.version)?;
            return Ok(InstallResult {
                install_dir: self.install_dir.clone(),
                version: appinstaller.version,
                dbgx_path,
                installed: false,
                updated: false,
            });
        }

        let temp_dir = self.install_dir.join(".download");
        if temp_dir.exists() {
            fs::remove_dir_all(&temp_dir)
                .with_context(|| format!("removing {}", temp_dir.display()))?;
        }
        fs::create_dir_all(&temp_dir)
            .with_context(|| format!("creating {}", temp_dir.display()))?;

        let bundle_path = temp_dir.join("windbg.msixbundle");
        download_file(&appinstaller.bundle_uri, &bundle_path)
            .with_context(|| format!("downloading {}", appinstaller.bundle_uri))?;

        let package = select_bundle_package(&bundle_path, native_architecture()?)?;
        ensure!(
            is_safe_single_component(&package.file_name),
            "bundle package FileName is not a safe filename: {:?}",
            package.file_name
        );
        let msix_path = temp_dir.join(&package.file_name);
        extract_one_from_zip(&bundle_path, &package.file_name, &msix_path)?;
        verify_msix_trust(&msix_path)?;

        if version_dir.exists() {
            fs::remove_dir_all(&version_dir)
                .with_context(|| format!("removing {}", version_dir.display()))?;
        }
        fs::create_dir_all(&version_dir)
            .with_context(|| format!("creating {}", version_dir.display()))?;
        extract_zip_safely(&msix_path, &version_dir)?;
        ensure!(
            dbgx_path.is_file(),
            "extracted WinDbg package did not contain {}",
            dbgx_path.display()
        );

        self.write_installed_version(&appinstaller.version)?;
        let _ = fs::remove_dir_all(&temp_dir);

        Ok(InstallResult {
            install_dir: self.install_dir.clone(),
            version: appinstaller.version,
            dbgx_path,
            installed: true,
            updated: previous_version.is_some(),
        })
    }

    pub fn update(&self) -> anyhow::Result<InstallResult> {
        self.install(false)
    }

    pub fn dbgx_path(&self) -> anyhow::Result<PathBuf> {
        let version = self
            .installed_version()?
            .context("WinDbg is not installed; run `windbg-tool windbg install` first")?;
        let path = self.version_dir(&version)?.join("DbgX.Shell.exe");
        ensure!(
            path.is_file(),
            "installed WinDbg executable is missing at {}",
            path.display()
        );
        Ok(path)
    }

    fn fetch_appinstaller(&self) -> anyhow::Result<AppInstallerInfo> {
        let text = reqwest::blocking::get(&self.appinstaller_url)
            .with_context(|| format!("fetching {}", self.appinstaller_url))?
            .error_for_status()
            .with_context(|| format!("fetching {}", self.appinstaller_url))?
            .text()
            .context("reading appinstaller response")?;
        parse_appinstaller(&text)
    }

    fn version_dir(&self, version: &str) -> anyhow::Result<PathBuf> {
        ensure!(
            is_safe_single_component(version),
            "WinDbg version string is not a safe directory name: {version:?}"
        );
        Ok(self.install_dir.join(version))
    }

    fn installed_version(&self) -> anyhow::Result<Option<String>> {
        let version_file = self.install_dir.join("version.txt");
        if !version_file.exists() {
            return Ok(None);
        }
        let version = fs::read_to_string(&version_file)
            .with_context(|| format!("reading {}", version_file.display()))?
            .trim()
            .to_string();
        if version.is_empty() {
            return Ok(None);
        }
        ensure!(
            is_safe_single_component(&version),
            "installed version in {} is not a safe directory name: {version:?}",
            version_file.display()
        );
        Ok(Some(version))
    }

    fn write_installed_version(&self, version: &str) -> anyhow::Result<()> {
        fs::write(self.install_dir.join("version.txt"), version)
            .with_context(|| format!("writing {}", self.install_dir.join("version.txt").display()))
    }
}

pub fn default_install_dir() -> anyhow::Result<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is not set; pass --install-dir explicitly")?;
    Ok(local_app_data.join("windbg-tool").join("WinDbg"))
}

pub fn parse_appinstaller(xml: &str) -> anyhow::Result<AppInstallerInfo> {
    let document = roxmltree::Document::parse(xml).context("parsing appinstaller XML")?;
    let root = document
        .descendants()
        .find(|node| node.has_tag_name("AppInstaller"))
        .context("appinstaller XML does not contain AppInstaller root")?;
    let version = root
        .attribute("Version")
        .context("AppInstaller is missing Version")?
        .to_string();
    ensure!(
        is_safe_single_component(&version),
        "AppInstaller Version is not a safe directory name: {version:?}"
    );
    let bundle = document
        .descendants()
        .find(|node| node.has_tag_name("MainBundle"))
        .context("appinstaller XML does not contain MainBundle")?;
    let bundle_uri = bundle
        .attribute("Uri")
        .context("MainBundle is missing Uri")?
        .to_string();
    Ok(AppInstallerInfo {
        version,
        bundle_uri,
    })
}

pub fn parse_bundle_manifest(xml: &str) -> anyhow::Result<Vec<BundlePackage>> {
    let document = roxmltree::Document::parse(xml).context("parsing bundle manifest XML")?;
    let packages = document
        .descendants()
        .filter(|node| node.has_tag_name("Package"))
        // Resource packages (language/scale packs) usually omit Architecture,
        // which would otherwise make them look like installable neutral
        // application packages.
        .filter(|node| {
            !node
                .attribute("Type")
                .is_some_and(|kind| kind.eq_ignore_ascii_case("resource"))
        })
        .filter_map(|node| {
            Some(BundlePackage {
                file_name: node.attribute("FileName")?.to_string(),
                architecture: node
                    .attribute("Architecture")
                    .unwrap_or("neutral")
                    .to_string(),
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        !packages.is_empty(),
        "bundle manifest did not contain any package entries"
    );
    Ok(packages)
}

pub fn select_package(
    packages: &[BundlePackage],
    arch: Architecture,
) -> anyhow::Result<BundlePackage> {
    let preferred = arch.as_bundle_str();
    packages
        .iter()
        .find(|package| package.architecture.eq_ignore_ascii_case(preferred))
        .or_else(|| {
            packages
                .iter()
                .find(|package| package.architecture.eq_ignore_ascii_case("neutral"))
        })
        .cloned()
        .with_context(|| format!("bundle does not contain a {preferred} package"))
}

fn select_bundle_package(bundle_path: &Path, arch: Architecture) -> anyhow::Result<BundlePackage> {
    let file =
        File::open(bundle_path).with_context(|| format!("opening {}", bundle_path.display()))?;
    let mut zip =
        ZipArchive::new(file).with_context(|| format!("reading {}", bundle_path.display()))?;
    let mut manifest = zip
        .by_name("AppxMetadata/AppxBundleManifest.xml")
        .context("bundle is missing AppxMetadata/AppxBundleManifest.xml")?;
    let mut xml = String::new();
    io::Read::read_to_string(&mut manifest, &mut xml).context("reading bundle manifest")?;
    let packages = parse_bundle_manifest(&xml)?;
    select_package(&packages, arch)
}

fn download_file(url: &str, destination: &Path) -> anyhow::Result<()> {
    // `reqwest::blocking::get` applies a 30 second total timeout that also
    // covers reading the body, which is far too short for the multi-hundred
    // megabyte WinDbg bundle on typical connections.
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(None::<Duration>)
        .build()
        .context("creating WinDbg download client")?;
    let mut response = client
        .get(url)
        .send()
        .with_context(|| format!("requesting {url}"))?
        .error_for_status()
        .with_context(|| format!("requesting {url}"))?;
    let mut file =
        File::create(destination).with_context(|| format!("creating {}", destination.display()))?;
    io::copy(&mut response, &mut file)
        .with_context(|| format!("writing {}", destination.display()))?;
    Ok(())
}

fn extract_one_from_zip(
    zip_path: &Path,
    entry_name: &str,
    destination: &Path,
) -> anyhow::Result<()> {
    let file = File::open(zip_path).with_context(|| format!("opening {}", zip_path.display()))?;
    let mut zip =
        ZipArchive::new(file).with_context(|| format!("reading {}", zip_path.display()))?;
    let mut entry = zip
        .by_name(entry_name)
        .with_context(|| format!("bundle is missing selected package {entry_name}"))?;
    let mut output =
        File::create(destination).with_context(|| format!("creating {}", destination.display()))?;
    io::copy(&mut entry, &mut output)
        .with_context(|| format!("extracting {entry_name} to {}", destination.display()))?;
    Ok(())
}

fn extract_zip_safely(zip_path: &Path, destination: &Path) -> anyhow::Result<()> {
    let file = File::open(zip_path).with_context(|| format!("opening {}", zip_path.display()))?;
    let mut zip =
        ZipArchive::new(file).with_context(|| format!("reading {}", zip_path.display()))?;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).context("reading archive entry")?;
        let Some(enclosed_name) = entry.enclosed_name() else {
            bail!("archive entry escapes destination: {}", entry.name());
        };
        let output_path = destination.join(enclosed_name);
        if entry.is_dir() {
            fs::create_dir_all(&output_path)
                .with_context(|| format!("creating {}", output_path.display()))?;
            continue;
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut output = File::create(&output_path)
            .with_context(|| format!("creating {}", output_path.display()))?;
        io::copy(&mut entry, &mut output)
            .with_context(|| format!("extracting {}", output_path.display()))?;
    }
    Ok(())
}

fn native_architecture() -> anyhow::Result<Architecture> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Architecture::X64),
        "x86" => Ok(Architecture::X86),
        "aarch64" => Ok(Architecture::Arm64),
        arch => bail!("unsupported host architecture for WinDbg package selection: {arch}"),
    }
}

impl Architecture {
    fn as_bundle_str(self) -> &'static str {
        match self {
            Architecture::X64 => "x64",
            Architecture::X86 => "x86",
            Architecture::Arm64 => "arm64",
        }
    }
}

fn verify_msix_trust(path: &Path) -> anyhow::Result<()> {
    verify_msix_trust_impl(path)
}

#[cfg(windows)]
fn verify_msix_trust_impl(path: &Path) -> anyhow::Result<()> {
    let script = r#"
$signature = Get-AuthenticodeSignature -LiteralPath $env:WINDBG_MSIX_PATH
if ($signature.Status -ne 'Valid') {
    Write-Error "Authenticode signature status is $($signature.Status)"
    exit 1
}
if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft\b') {
    Write-Error "Signer certificate is not a Microsoft certificate"
    exit 2
}
"#;
    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(script)
        .env("WINDBG_MSIX_PATH", path)
        .output()
        .with_context(|| format!("verifying Authenticode signature for {}", path.display()))?;
    if !output.status.success() {
        bail!(
            "WinDbg package signature verification failed for {}\nstdout:\n{}\nstderr:\n{}",
            path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn is_safe_single_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !name.contains(['/', '\\', ':', '\0'])
        && !name.chars().any(char::is_control)
        && Path::new(name)
            .file_name()
            .is_some_and(|file_name| file_name == name)
}

#[cfg(not(windows))]
fn verify_msix_trust_impl(path: &Path) -> anyhow::Result<()> {
    let _ = path;
    bail!("WinDbg MSIX trust verification is only supported on Windows")
}

struct InstallLock {
    path: PathBuf,
}

impl InstallLock {
    fn acquire(install_dir: &Path) -> anyhow::Result<Self> {
        let path = install_dir.join(".install.lock");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "acquiring install lock {}; another windbg-tool install/update may be running",
                    path.display()
                )
            })?;
        Ok(Self { path })
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_manifest_skips_resource_packages() {
        let packages = parse_bundle_manifest(
            r#"
            <Bundle>
              <Packages>
                <Package Type="application" FileName="windbg-x64.msix" Architecture="x64" />
                <Package Type="resource" FileName="windbg-scale-100.msix" ResourceId="split.scale-100" />
              </Packages>
            </Bundle>
            "#,
        )
        .unwrap();
        assert_eq!(packages.len(), 1);
        assert!(select_package(&packages, Architecture::X86).is_err());
    }
}
