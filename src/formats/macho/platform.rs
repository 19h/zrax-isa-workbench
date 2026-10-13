//! `LC_BUILD_VERSION` and `LC_VERSION_MIN_*`: platform and OS versions.
//!
//! `build_version_command` (24 B): `platform` at 8, `minos` at 12, `sdk` at
//! 16, `ntools` at 20, then `ntools` 8-byte `build_tool_version` records.
//! `version_min_command` (16 B): `version` at 8, `sdk` at 12. Versions are
//! "X.Y.Z encoded in nibbles xxxx.yy.zz".

use super::commands::{
    Command, LC_BUILD_VERSION, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
};
use super::*;

const BUILD_VERSION_COMMAND_SIZE: usize = 24;
const BUILD_TOOL_VERSION_SIZE: usize = 8;
const VERSION_MIN_COMMAND_SIZE: usize = 16;

/// `PLATFORM_*` values: xnu `loader.h` defines 1 to 12; cctools-1035.1.102
/// adds `PLATFORM_UNKNOWN` and 13 to 24 (and renames 11 and 12
/// `PLATFORM_VISIONOS*`).
const PLATFORM_UNKNOWN: u32 = 0;
const PLATFORM_MACOS: u32 = 1;
const PLATFORM_IOS: u32 = 2;
const PLATFORM_TVOS: u32 = 3;
const PLATFORM_WATCHOS: u32 = 4;
const PLATFORM_BRIDGEOS: u32 = 5;
const PLATFORM_MACCATALYST: u32 = 6;
const PLATFORM_IOSSIMULATOR: u32 = 7;
const PLATFORM_TVOSSIMULATOR: u32 = 8;
const PLATFORM_WATCHOSSIMULATOR: u32 = 9;
const PLATFORM_DRIVERKIT: u32 = 10;
const PLATFORM_XROS: u32 = 11;
const PLATFORM_XROSSIMULATOR: u32 = 12;
const PLATFORM_FIRMWARE: u32 = 13;
const PLATFORM_SEPOS: u32 = 14;
const PLATFORM_MACOS_EXCLAVECORE: u32 = 15;
const PLATFORM_MACOS_EXCLAVEKIT: u32 = 16;
const PLATFORM_IOS_EXCLAVECORE: u32 = 17;
const PLATFORM_IOS_EXCLAVEKIT: u32 = 18;
const PLATFORM_TVOS_EXCLAVECORE: u32 = 19;
const PLATFORM_TVOS_EXCLAVEKIT: u32 = 20;
const PLATFORM_WATCHOS_EXCLAVECORE: u32 = 21;
const PLATFORM_WATCHOS_EXCLAVEKIT: u32 = 22;
const PLATFORM_VISIONOS_EXCLAVECORE: u32 = 23;
const PLATFORM_VISIONOS_EXCLAVEKIT: u32 = 24;

/// Read an `LC_BUILD_VERSION`; its tool records must fit `cmdsize`.
pub(super) fn read_build_version(command: &Command<'_>) -> Result<BuildVersion> {
    command.expect_size(BUILD_VERSION_COMMAND_SIZE)?;
    let tools = command.u32_at(20)? as usize;
    let tools_size = command.bytes.len() - BUILD_VERSION_COMMAND_SIZE;
    if tools > tools_size / BUILD_TOOL_VERSION_SIZE {
        return Err(error(format!(
            "Invalid LC_BUILD_VERSION at 0x{:X}: ntools {tools} does not fit cmdsize {} B",
            command.offset,
            command.bytes.len()
        )));
    }
    Ok(BuildVersion {
        command: LC_BUILD_VERSION,
        platform: command.u32_at(8)?,
        min_os: command.u32_at(12)?,
        sdk: command.u32_at(16)?,
    })
}

/// The platform an `LC_VERSION_MIN_*` command names.
fn version_min_platform(cmd: u32) -> Option<u32> {
    match cmd {
        LC_VERSION_MIN_MACOSX => Some(PLATFORM_MACOS),
        LC_VERSION_MIN_IPHONEOS => Some(PLATFORM_IOS),
        LC_VERSION_MIN_TVOS => Some(PLATFORM_TVOS),
        LC_VERSION_MIN_WATCHOS => Some(PLATFORM_WATCHOS),
        _ => None,
    }
}

/// Read an `LC_VERSION_MIN_*`; the command names the platform.
pub(super) fn read_version_min(command: &Command<'_>) -> Result<BuildVersion> {
    command.expect_size(VERSION_MIN_COMMAND_SIZE)?;
    let platform = version_min_platform(command.cmd).ok_or_else(|| {
        error(format!(
            "Invalid {} at 0x{:X}: not an LC_VERSION_MIN_* command",
            command.name(),
            command.offset
        ))
    })?;
    Ok(BuildVersion {
        command: command.cmd,
        platform,
        min_os: command.u32_at(8)?,
        sdk: command.u32_at(12)?,
    })
}

/// Display name of a `PLATFORM_*` value.
pub(super) fn platform_name(platform: u32) -> Option<&'static str> {
    let name = match platform {
        PLATFORM_UNKNOWN => "unknown (PLATFORM_UNKNOWN)",
        PLATFORM_MACOS => "macOS",
        PLATFORM_IOS => "iOS",
        PLATFORM_TVOS => "tvOS",
        PLATFORM_WATCHOS => "watchOS",
        PLATFORM_BRIDGEOS => "bridgeOS",
        PLATFORM_MACCATALYST => "Mac Catalyst",
        PLATFORM_IOSSIMULATOR => "iOS Simulator",
        PLATFORM_TVOSSIMULATOR => "tvOS Simulator",
        PLATFORM_WATCHOSSIMULATOR => "watchOS Simulator",
        PLATFORM_DRIVERKIT => "DriverKit",
        PLATFORM_XROS => "visionOS",
        PLATFORM_XROSSIMULATOR => "visionOS Simulator",
        PLATFORM_FIRMWARE => "firmware",
        PLATFORM_SEPOS => "sepOS",
        PLATFORM_MACOS_EXCLAVECORE => "macOS ExclaveCore",
        PLATFORM_MACOS_EXCLAVEKIT => "macOS ExclaveKit",
        PLATFORM_IOS_EXCLAVECORE => "iOS ExclaveCore",
        PLATFORM_IOS_EXCLAVEKIT => "iOS ExclaveKit",
        PLATFORM_TVOS_EXCLAVECORE => "tvOS ExclaveCore",
        PLATFORM_TVOS_EXCLAVEKIT => "tvOS ExclaveKit",
        PLATFORM_WATCHOS_EXCLAVECORE => "watchOS ExclaveCore",
        PLATFORM_WATCHOS_EXCLAVEKIT => "watchOS ExclaveKit",
        PLATFORM_VISIONOS_EXCLAVECORE => "visionOS ExclaveCore",
        PLATFORM_VISIONOS_EXCLAVEKIT => "visionOS ExclaveKit",
        _ => return None,
    };
    Some(name)
}

impl BuildVersion {
    /// The platform's display name, or its value in hex.
    pub fn platform_label(&self) -> String {
        platform_name(self.platform).map_or_else(
            || format!("0x{:X} (not a known PLATFORM_* value)", self.platform),
            String::from,
        )
    }
}

/// A `xxxx.yy.zz` version as text: `14.0`, or `10.13.6` when the patch
/// level is not 0.
pub(super) fn version_text(version: u32) -> String {
    let major = version >> 16;
    let minor = (version >> 8) & 0xFF;
    let patch = version & 0xFF;
    if patch == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{patch}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_decoded_from_nibbles() {
        assert_eq!(version_text(0x000E_0000), "14.0");
        assert_eq!(version_text(0x000A_0D06), "10.13.6");
        assert_eq!(version_text(0), "0.0");
    }

    #[test]
    fn simulator_and_exclave_platforms_have_names() {
        assert_eq!(platform_name(7), Some("iOS Simulator"));
        assert_eq!(platform_name(11), Some("visionOS"));
        assert_eq!(platform_name(24), Some("visionOS ExclaveKit"));
        assert_eq!(platform_name(25), None);
    }
}
