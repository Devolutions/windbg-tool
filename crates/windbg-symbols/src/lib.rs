use anyhow::{bail, ensure, Context};
use reqwest::blocking::Client;
use reqwest::header::LOCATION;
use reqwest::Url;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MICROSOFT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const OPTIONAL_HEADER_PE32: u16 = 0x10b;
const OPTIONAL_HEADER_PE32_PLUS: u16 = 0x20b;
const MAX_IMAGE_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
const IMAGE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const IMAGE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeViewIdentity {
    pub pdb_name: String,
    pub pdb_guid: String,
    pub pdb_age: u32,
    pub pdb_store_key: String,
    pub pdb_store_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeIdentity {
    pub image_name: String,
    pub image_timestamp: u32,
    pub image_size: u32,
    pub image_store_key: String,
    pub image_store_path: String,
    pub codeview: CodeViewIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeImageIdentity {
    pub image_name: String,
    pub image_timestamp: u32,
    pub image_size: u32,
    pub image_store_key: String,
    pub image_store_path: String,
}

impl PeImageIdentity {
    pub fn new(
        image_name: impl Into<String>,
        image_timestamp: u32,
        image_size: u32,
    ) -> anyhow::Result<Self> {
        let image_name = image_name.into();
        ensure!(
            is_safe_file_name(&image_name),
            "PE image filename must be a basename without path separators"
        );
        let image_store_key = format!("{image_timestamp:X}{image_size:X}");
        Ok(Self {
            image_store_path: format!("{image_name}\\{image_store_key}\\{image_name}"),
            image_name,
            image_timestamp,
            image_size,
            image_store_key,
        })
    }
}

pub fn inspect_pe_identity(path: &Path) -> anyhow::Result<PeIdentity> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    inspect_pe_identity_bytes(&data, path.file_name().and_then(|name| name.to_str()))
}

pub fn inspect_pe_identity_bytes(
    data: &[u8],
    image_name: Option<&str>,
) -> anyhow::Result<PeIdentity> {
    let pe_offset = read_u32(data, 0x3c)? as usize;
    ensure!(
        read_bytes(data, pe_offset, 4)? == b"PE\0\0",
        "missing PE signature"
    );

    let file_header = pe_offset + 4;
    let section_count = read_u16(data, file_header + 2)? as usize;
    let timestamp = read_u32(data, file_header + 4)?;
    let optional_size = read_u16(data, file_header + 16)? as usize;
    let optional = file_header + 20;
    let magic = read_u16(data, optional)?;
    let data_dir_base = match magic {
        OPTIONAL_HEADER_PE32 => optional + 96,
        OPTIONAL_HEADER_PE32_PLUS => optional + 112,
        _ => bail!("unsupported PE optional header magic 0x{magic:04x}"),
    };
    let image_size = read_u32(data, optional + 56)?;
    let section_table = optional + optional_size;
    let sections = read_sections(data, section_table, section_count)?;

    let debug_dir = data_dir_base + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
    let debug_rva = read_u32(data, debug_dir)?;
    let debug_size = read_u32(data, debug_dir + 4)?;
    ensure!(
        debug_rva != 0 && debug_size != 0,
        "PE has no CodeView debug directory"
    );
    let debug_offset = rva_to_file_offset(debug_rva, &sections)
        .with_context(|| format!("mapping debug directory RVA 0x{debug_rva:x}"))?;
    let codeview = read_codeview(data, debug_offset, debug_size as usize)?
        .context("PE has no RSDS CodeView record")?;
    let image_name = image_name
        .filter(|name| !name.is_empty())
        .context("PE image filename is required for symbol resolution")?
        .to_string();
    let image_store_key = format!("{timestamp:X}{image_size:X}");
    Ok(PeIdentity {
        image_store_path: format!("{image_name}\\{image_store_key}\\{image_name}"),
        image_name,
        image_timestamp: timestamp,
        image_size,
        image_store_key,
        codeview,
    })
}

pub fn inspect_pe_image_identity(path: &Path) -> anyhow::Result<PeImageIdentity> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    inspect_pe_image_identity_bytes(&data, path.file_name().and_then(|name| name.to_str()))
}

pub fn inspect_pe_image_identity_bytes(
    data: &[u8],
    image_name: Option<&str>,
) -> anyhow::Result<PeImageIdentity> {
    let pe_offset = read_u32(data, 0x3c)? as usize;
    ensure!(
        read_bytes(data, pe_offset, 4)? == b"PE\0\0",
        "missing PE signature"
    );
    let file_header = pe_offset + 4;
    let timestamp = read_u32(data, file_header + 4)?;
    let optional = file_header + 20;
    let magic = read_u16(data, optional)?;
    ensure!(
        matches!(magic, OPTIONAL_HEADER_PE32 | OPTIONAL_HEADER_PE32_PLUS),
        "unsupported PE optional header magic 0x{magic:04x}"
    );
    let image_size = read_u32(data, optional + 56)?;
    let image_name = image_name
        .filter(|name| !name.is_empty())
        .context("PE image filename is required for symbol resolution")?;
    PeImageIdentity::new(image_name, timestamp, image_size)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeSymbolStatus {
    Cached,
    Downloaded,
    OfflineMissing,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeSymbolResult {
    pub status: NativeSymbolStatus,
    pub identity: PeIdentity,
    pub cache_dir: PathBuf,
    pub pdb_path: Option<PathBuf>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeImageStatus {
    Local,
    Cached,
    Downloaded,
    OfflineMissing,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeImageResult {
    pub status: NativeImageStatus,
    pub identity: PeImageIdentity,
    pub cache_dir: PathBuf,
    pub image_path: Option<PathBuf>,
    pub detail: String,
}

pub fn image_matches(path: &Path, expected: &PeImageIdentity) -> anyhow::Result<bool> {
    let actual = inspect_pe_image_identity(path)?;
    Ok(actual.image_timestamp == expected.image_timestamp
        && actual.image_size == expected.image_size)
}

pub fn prefetch_image(
    expected: PeImageIdentity,
    cache_dir: &Path,
    offline: bool,
) -> anyhow::Result<NativeImageResult> {
    let expected_path = cache_dir.join(&expected.image_store_path);
    if expected_path.is_file() && image_matches(&expected_path, &expected).unwrap_or(false) {
        return Ok(NativeImageResult {
            status: NativeImageStatus::Cached,
            identity: expected,
            cache_dir: cache_dir.to_path_buf(),
            image_path: Some(expected_path),
            detail: "A matching PE image is already present in the native image cache.".to_string(),
        });
    }
    if offline {
        return Ok(NativeImageResult {
            status: NativeImageStatus::OfflineMissing,
            identity: expected,
            cache_dir: cache_dir.to_path_buf(),
            image_path: None,
            detail: "Offline mode prevented native PE image download and the matching image is absent from the cache.".to_string(),
        });
    }

    download_image(&expected, cache_dir)?;
    ensure!(
        image_matches(&expected_path, &expected)?,
        "downloaded PE image did not match the requested timestamp and SizeOfImage"
    );
    Ok(NativeImageResult {
        status: NativeImageStatus::Downloaded,
        identity: expected,
        cache_dir: cache_dir.to_path_buf(),
        image_path: Some(expected_path),
        detail: "Downloaded and validated the matching PE image with the Rust-native symbol-server client.".to_string(),
    })
}

pub fn prefetch_pdb(
    image_path: &Path,
    cache_dir: &Path,
    offline: bool,
) -> anyhow::Result<NativeSymbolResult> {
    let identity = inspect_pe_identity(image_path)?;
    let expected_path = cache_dir.join(&identity.codeview.pdb_store_path);
    if expected_path.is_file() {
        return Ok(NativeSymbolResult {
            status: NativeSymbolStatus::Cached,
            identity,
            cache_dir: cache_dir.to_path_buf(),
            pdb_path: Some(expected_path),
            detail: "A matching PDB is already present in the native symbol cache.".to_string(),
        });
    }
    if offline {
        return Ok(NativeSymbolResult {
            status: NativeSymbolStatus::OfflineMissing,
            identity,
            cache_dir: cache_dir.to_path_buf(),
            pdb_path: None,
            detail: "Offline mode prevented native symbol download and the matching PDB is absent from the cache.".to_string(),
        });
    }
    let downloaded_path = download_pdb(&identity.codeview, cache_dir)?;
    Ok(NativeSymbolResult {
        status: NativeSymbolStatus::Downloaded,
        identity,
        cache_dir: cache_dir.to_path_buf(),
        pdb_path: Some(downloaded_path),
        detail: "Downloaded the matching PDB with the Rust-native symbol-server client."
            .to_string(),
    })
}

fn download_pdb(identity: &CodeViewIdentity, cache_dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("creating native symbol cache {}", cache_dir.display()))?;
    let cache_dir = cache_dir.to_path_buf();
    let identity = identity.clone();
    run_async(async move {
        let symbol_path = format!("srv*{}*{}", cache_dir.display(), MICROSOFT_SYMBOL_SERVER);
        let mut downloader =
            symsrv::SymsrvDownloader::new(symsrv::parse_nt_symbol_path(&symbol_path));
        downloader.set_default_downstream_store(Some(cache_dir.clone()));
        downloader
            .get_file(&identity.pdb_name, &identity.pdb_store_key)
            .await
            .with_context(|| {
                format!(
                    "downloading {} from {}",
                    identity.pdb_store_path, MICROSOFT_SYMBOL_SERVER
                )
            })
    })
}

fn download_image(identity: &PeImageIdentity, cache_dir: &Path) -> anyhow::Result<()> {
    let identity = identity.clone();
    let cache_dir = cache_dir.to_path_buf();
    std::thread::Builder::new()
        .name("windbg-symbol-image-download".to_string())
        .spawn(move || download_image_blocking(&identity, &cache_dir))
        .context("starting native PE image download thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("native PE image download thread panicked"))?
}

fn download_image_blocking(identity: &PeImageIdentity, cache_dir: &Path) -> anyhow::Result<()> {
    let target = cache_dir.join(&identity.image_store_path);
    let parent = target.parent().context("image cache path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating native image cache {}", parent.display()))?;
    let mut response = get_microsoft_response(image_download_url(identity)?)?;
    if let Some(content_length) = response.content_length() {
        ensure!(
            content_length <= MAX_IMAGE_DOWNLOAD_BYTES,
            "native PE image download exceeds the {} MiB limit",
            MAX_IMAGE_DOWNLOAD_BYTES / (1024 * 1024)
        );
    }

    let temporary = parent.join(format!(
        ".{}.{}.download",
        identity.image_name,
        std::process::id()
    ));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| {
            format!(
                "creating temporary image cache file {}",
                temporary.display()
            )
        })?;
    let download = (|| -> anyhow::Result<()> {
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = response
                .read(&mut buffer)
                .context("reading native PE image response")?;
            if read == 0 {
                break;
            }
            copied += read as u64;
            ensure!(
                copied <= MAX_IMAGE_DOWNLOAD_BYTES,
                "native PE image download exceeds the {} MiB limit",
                MAX_IMAGE_DOWNLOAD_BYTES / (1024 * 1024)
            );
            output
                .write_all(&buffer[..read])
                .context("writing temporary native PE image")?;
        }
        output
            .sync_all()
            .context("flushing temporary native PE image")?;
        Ok(())
    })();
    drop(output);
    if let Err(error) = download {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, &target) {
        if target.is_file() {
            let _ = fs::remove_file(&temporary);
            return Ok(());
        }
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| {
            format!(
                "atomically moving native PE image {} into {}",
                temporary.display(),
                target.display()
            )
        });
    }
    Ok(())
}

fn image_download_url(identity: &PeImageIdentity) -> anyhow::Result<Url> {
    let url = Url::parse(&format!(
        "{}/{}",
        MICROSOFT_SYMBOL_SERVER,
        identity.image_store_path.replace('\\', "/")
    ))
    .context("building Microsoft Symbol Server image URL")?;
    ensure_microsoft_symbol_url(&url)?;
    Ok(url)
}

fn get_microsoft_response(mut url: Url) -> anyhow::Result<reqwest::blocking::Response> {
    let client = Client::builder()
        .connect_timeout(IMAGE_CONNECT_TIMEOUT)
        .timeout(IMAGE_DOWNLOAD_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("creating native image download client")?;
    for _ in 0..=MAX_REDIRECTS {
        ensure_microsoft_symbol_url(&url)?;
        let response = client
            .get(url.clone())
            .send()
            .with_context(|| format!("downloading native PE image from {url}"))?;
        if response.status().is_success() {
            return Ok(response);
        }
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(LOCATION)
                .context("Microsoft Symbol Server redirect omitted Location")?
                .to_str()
                .context("Microsoft Symbol Server redirect Location was not valid text")?;
            url = url
                .join(location)
                .context("resolving Microsoft Symbol Server redirect")?;
            continue;
        }
        bail!(
            "Microsoft Symbol Server returned HTTP {} for native PE image",
            response.status()
        );
    }
    bail!("Microsoft Symbol Server exceeded {MAX_REDIRECTS} native PE image redirects")
}

fn ensure_microsoft_symbol_url(url: &Url) -> anyhow::Result<()> {
    ensure!(
        url.scheme() == "https",
        "native symbol downloads require HTTPS"
    );
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let allowed = matches!(
        host.as_str(),
        "msdl.microsoft.com" | "download.microsoft.com"
    ) || (host.starts_with("vsblobprod") && host.ends_with(".blob.core.windows.net"));
    ensure!(
        allowed,
        "native symbol download redirect host {host:?} is not in the Microsoft allowlist"
    );
    Ok(())
}

fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && Path::new(name)
            .file_name()
            .is_some_and(|file_name| file_name == name)
        && !name.contains(['/', '\\'])
}

fn run_async<T: Send + 'static>(
    future: impl std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
) -> anyhow::Result<T> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("creating native symbol download runtime")?
            .block_on(future),
    }
}

#[derive(Debug, Clone)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn read_sections(data: &[u8], offset: usize, count: usize) -> anyhow::Result<Vec<Section>> {
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let offset = offset + index * 40;
        sections.push(Section {
            virtual_size: read_u32(data, offset + 8)?,
            virtual_address: read_u32(data, offset + 12)?,
            raw_size: read_u32(data, offset + 16)?,
            raw_offset: read_u32(data, offset + 20)?,
        });
    }
    Ok(sections)
}

fn rva_to_file_offset(rva: u32, sections: &[Section]) -> anyhow::Result<usize> {
    sections
        .iter()
        .find_map(|section| {
            let size = section.virtual_size.max(section.raw_size);
            (rva >= section.virtual_address && rva < section.virtual_address.saturating_add(size))
                .then_some(section.raw_offset as usize + (rva - section.virtual_address) as usize)
        })
        .context("RVA does not map to a PE section")
}

fn read_codeview(
    data: &[u8],
    directory_offset: usize,
    directory_size: usize,
) -> anyhow::Result<Option<CodeViewIdentity>> {
    for index in 0..directory_size / 28 {
        let offset = directory_offset + index * 28;
        if read_u32(data, offset + 12)? != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let size = read_u32(data, offset + 16)? as usize;
        let raw_offset = read_u32(data, offset + 24)? as usize;
        let payload = read_bytes(data, raw_offset, size)?;
        if payload.len() < 24 || &payload[..4] != b"RSDS" {
            continue;
        }
        let guid = pdb_guid_string(&payload[4..20]);
        let age = read_u32(payload, 20)?;
        let pdb_path = read_null_terminated_string(&payload[24..]);
        let pdb_name = Path::new(&pdb_path)
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .context("RSDS CodeView record has no PDB filename")?
            .to_string();
        let pdb_store_key = format!("{guid}{age:X}");
        return Ok(Some(CodeViewIdentity {
            pdb_store_path: format!("{pdb_name}\\{pdb_store_key}\\{pdb_name}"),
            pdb_name,
            pdb_guid: guid,
            pdb_age: age,
            pdb_store_key,
        }));
    }
    Ok(None)
}

fn read_bytes(data: &[u8], offset: usize, size: usize) -> anyhow::Result<&[u8]> {
    data.get(offset..offset.saturating_add(size))
        .context("PE record is outside the input file")
}

fn read_u16(data: &[u8], offset: usize) -> anyhow::Result<u16> {
    let bytes: [u8; 2] = read_bytes(data, offset, 2)?
        .try_into()
        .expect("fixed-size slice");
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> anyhow::Result<u32> {
    let bytes: [u8; 4] = read_bytes(data, offset, 4)?
        .try_into()
        .expect("fixed-size slice");
    Ok(u32::from_le_bytes(bytes))
}

fn read_null_terminated_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn pdb_guid_string(bytes: &[u8]) -> String {
    let d1 = u32::from_le_bytes(bytes[0..4].try_into().expect("GUID d1"));
    let d2 = u16::from_le_bytes(bytes[4..6].try_into().expect("GUID d2"));
    let d3 = u16::from_le_bytes(bytes[6..8].try_into().expect("GUID d3"));
    format!(
        "{d1:08X}{d2:04X}{d3:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rsds_identity_has_the_documented_symbol_store_key() {
        let bytes = [
            0x23, 0xBC, 0x24, 0x19, 0x09, 0x55, 0xF8, 0x19, 0x8B, 0x17, 0xA3, 0x84, 0xB9, 0x44,
            0xB5, 0x43,
        ];
        let guid = pdb_guid_string(&bytes);
        assert_eq!(guid, "1924BC23550919F88B17A384B944B543");
    }

    #[test]
    fn image_store_url_uses_timestamp_and_image_size() {
        let identity = PeImageIdentity::new("ntoskrnl.exe", 0x90B0_83DA, 0x0145_0000).unwrap();

        assert_eq!(identity.image_store_key, "90B083DA1450000");
        assert_eq!(
            image_download_url(&identity).unwrap().as_str(),
            "https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/90B083DA1450000/ntoskrnl.exe"
        );
    }

    #[test]
    fn image_download_allowlist_accepts_only_microsoft_symbol_hosts() {
        assert!(ensure_microsoft_symbol_url(
            &Url::parse("https://msdl.microsoft.com/download/symbols/").unwrap()
        )
        .is_ok());
        assert!(ensure_microsoft_symbol_url(
            &Url::parse("https://vsblobprodscussu5shard42.blob.core.windows.net/image").unwrap()
        )
        .is_ok());
        assert!(
            ensure_microsoft_symbol_url(&Url::parse("https://example.com/image").unwrap()).is_err()
        );
        assert!(ensure_microsoft_symbol_url(
            &Url::parse("http://msdl.microsoft.com/download/symbols/").unwrap()
        )
        .is_err());
    }

    #[test]
    fn image_identity_rejects_mismatched_timestamp_or_size() {
        let bytes = test_pe_header(0x4A63_AF4E, 0x0145_0000);
        let observed = inspect_pe_image_identity_bytes(&bytes, Some("ntoskrnl.exe")).unwrap();
        let expected = PeImageIdentity::new("ntoskrnl.exe", 0x90B0_83DA, 0x0145_0000).unwrap();

        assert_ne!(observed.image_timestamp, expected.image_timestamp);
        assert_eq!(observed.image_size, expected.image_size);
    }

    #[test]
    fn image_cache_and_offline_mode_do_not_contact_the_network() {
        let cache = test_directory();
        let identity = PeImageIdentity::new("ntoskrnl.exe", 0x90B0_83DA, 0x0145_0000).unwrap();

        let missing = prefetch_image(identity.clone(), &cache, true).unwrap();
        assert_eq!(missing.status, NativeImageStatus::OfflineMissing);
        assert!(missing.image_path.is_none());

        let cached_path = cache.join(&identity.image_store_path);
        fs::create_dir_all(cached_path.parent().unwrap()).unwrap();
        fs::write(
            &cached_path,
            test_pe_header(identity.image_timestamp, identity.image_size),
        )
        .unwrap();

        let cached = prefetch_image(identity, &cache, true).unwrap();
        assert_eq!(cached.status, NativeImageStatus::Cached);
        assert_eq!(cached.image_path.as_deref(), Some(cached_path.as_path()));
        fs::remove_dir_all(cache).unwrap();
    }

    fn test_pe_header(timestamp: u32, image_size: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let file_header = 0x84;
        bytes[file_header + 4..file_header + 8].copy_from_slice(&timestamp.to_le_bytes());
        let optional = file_header + 20;
        bytes[optional..optional + 2].copy_from_slice(&OPTIONAL_HEADER_PE32_PLUS.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&image_size.to_le_bytes());
        bytes
    }

    fn test_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "windbg-symbols-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
