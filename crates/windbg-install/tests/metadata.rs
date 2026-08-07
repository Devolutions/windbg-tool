use windbg_install::{
    parse_appinstaller, parse_bundle_manifest, select_package, Architecture, BundlePackage,
};

#[test]
fn parses_appinstaller_main_bundle() -> anyhow::Result<()> {
    let info = parse_appinstaller(
        r#"
        <AppInstaller Version="1.2.3.4" xmlns="http://schemas.microsoft.com/appx/appinstaller/2018">
          <MainBundle Uri="https://example.test/windbg.msixbundle" />
        </AppInstaller>
        "#,
    )?;
    assert_eq!(info.version, "1.2.3.4");
    assert_eq!(info.bundle_uri, "https://example.test/windbg.msixbundle");
    Ok(())
}

#[test]
fn selects_arch_specific_bundle_package() -> anyhow::Result<()> {
    let packages = parse_bundle_manifest(
        r#"
        <Bundle>
          <Packages>
            <Package FileName="windbg-x86.msix" Architecture="x86" />
            <Package FileName="windbg-x64.msix" Architecture="x64" />
            <Package FileName="windbg-arm64.msix" Architecture="arm64" />
          </Packages>
        </Bundle>
        "#,
    )?;
    assert_eq!(
        select_package(&packages, Architecture::X64)?.file_name,
        "windbg-x64.msix"
    );
    assert_eq!(
        select_package(&packages, Architecture::Arm64)?.file_name,
        "windbg-arm64.msix"
    );
    Ok(())
}

#[test]
fn falls_back_to_neutral_package() -> anyhow::Result<()> {
    let packages = vec![BundlePackage {
        file_name: "windbg-neutral.msix".to_string(),
        architecture: "neutral".to_string(),
    }];
    assert_eq!(
        select_package(&packages, Architecture::X86)?.file_name,
        "windbg-neutral.msix"
    );
    Ok(())
}
