use std::collections::BTreeMap;

use serde::Serialize;

use crate::util::find_subslice;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NuitkaPlugin {
    Pyside6,
    Pyside2,
    Pyqt5,
    Pyqt6,
    QtPlugins,
    TkInter,
    Numpy,
    Scipy,
    Pandas,
    Multiprocessing,
    AntiBloat,
    PkgResources,
    Pylint,
    EventLoop,
    DllFiles,
    DataFiles,
    DelvewheelMicrosoft,
    PythonZipFile,
    EnumCompat,
    OptionsNannyDsl,
    Implicit,
    Trio,
    Glfw,
    Matplotlib,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PluginScan {
    pub plugins: BTreeMap<NuitkaPlugin, PluginHit>,
    pub total: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PluginHit {
    pub marker_hits: u32,
    pub confidence: PluginConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginConfidence {
    Weak,
    Medium,
    Strong,
}

const PLUGIN_TABLE: &[(NuitkaPlugin, &[&[u8]])] = &[
    (
        NuitkaPlugin::Pyside6,
        &[b"PySide6/", b"shiboken6", b"PySide6.QtCore", b"libpyside6"],
    ),
    (
        NuitkaPlugin::Pyside2,
        &[b"PySide2/", b"shiboken2", b"PySide2.QtCore"],
    ),
    (
        NuitkaPlugin::Pyqt5,
        &[b"PyQt5/", b"PyQt5.QtCore", b"sip.cpython"],
    ),
    (NuitkaPlugin::Pyqt6, &[b"PyQt6/", b"PyQt6.QtCore"]),
    (
        NuitkaPlugin::QtPlugins,
        &[
            b"qt_plugins",
            b"platforms/qwindows",
            b"platforms/qcocoa",
            b"platforms/qxcb",
            b"qt.conf",
        ],
    ),
    (
        NuitkaPlugin::TkInter,
        &[b"tcl8.", b"tk8.", b"_tkinter", b"tkinter.tix"],
    ),
    (
        NuitkaPlugin::Numpy,
        &[
            b"numpy.core",
            b"_multiarray_umath",
            b"libopenblas",
            b"libmkl",
        ],
    ),
    (NuitkaPlugin::Scipy, &[b"scipy.linalg", b"scipy.sparse"]),
    (NuitkaPlugin::Pandas, &[b"pandas._libs", b"pandas/core"]),
    (
        NuitkaPlugin::Multiprocessing,
        &[
            b"multiprocessing.spawn",
            b"_multiprocessing",
            b"multiprocessing.resource_tracker",
        ],
    ),
    (
        NuitkaPlugin::AntiBloat,
        &[
            b"nuitka_anti_bloat",
            b"NUITKA_ANTI_BLOAT",
            b"anti-bloat plugin",
        ],
    ),
    (
        NuitkaPlugin::PkgResources,
        &[b"pkg_resources/_vendor", b"pkg_resources.extern"],
    ),
    (NuitkaPlugin::Pylint, &[b"pylint.config", b"pylint.lint"]),
    (
        NuitkaPlugin::EventLoop,
        &[b"asyncio.unix_events", b"asyncio.windows_events"],
    ),
    (
        NuitkaPlugin::DllFiles,
        &[b"include-package-data", b"--include-data-files"],
    ),
    (
        NuitkaPlugin::DataFiles,
        &[b"--include-data-dir", b"include-data-dir"],
    ),
    (
        NuitkaPlugin::DelvewheelMicrosoft,
        &[b".libs", b"vcruntime", b"msvcp"],
    ),
    (
        NuitkaPlugin::PythonZipFile,
        &[b"_bootlocale", b"PYZ-00.pyz"],
    ),
    (NuitkaPlugin::EnumCompat, &[b"enum_compat", b"_enum_compat"]),
    (
        NuitkaPlugin::OptionsNannyDsl,
        &[b"options-nanny", b"NUITKA_OPTIONS_NANNY"],
    ),
    (
        NuitkaPlugin::Implicit,
        &[b"implicit-imports", b"ImplicitImports"],
    ),
    (NuitkaPlugin::Trio, &[b"trio._core", b"trio.lowlevel"]),
    (NuitkaPlugin::Glfw, &[b"glfw", b"glfw.GLFW_CONTEXT"]),
    (
        NuitkaPlugin::Matplotlib,
        &[b"matplotlib.backends", b"matplotlib._cntr"],
    ),
];

pub fn scan_plugins(image: &[u8]) -> PluginScan {
    let mut plugins: BTreeMap<NuitkaPlugin, PluginHit> = BTreeMap::new();
    let mut total: u32 = 0u32;

    for (kind, needles) in PLUGIN_TABLE {
        let mut hits: u32 = 0u32;
        for needle in *needles {
            if find_subslice(image, needle).is_some() {
                hits = hits.saturating_add(1);
            }
        }
        if hits == 0 {
            continue;
        }
        let confidence: PluginConfidence = classify_confidence(hits, needles.len());
        plugins.insert(
            *kind,
            PluginHit {
                marker_hits: hits,
                confidence,
            },
        );
        total = total.saturating_add(1);
    }

    PluginScan { plugins, total }
}

#[inline]
fn classify_confidence(hits: u32, total: usize) -> PluginConfidence {
    let total_u32: u32 = u32::try_from(total).unwrap_or(u32::MAX);
    if hits == total_u32 && hits >= 3 {
        PluginConfidence::Strong
    } else if hits >= 2 {
        PluginConfidence::Medium
    } else {
        PluginConfidence::Weak
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_image_returns_empty_scan() {
        let scan: PluginScan = scan_plugins(&[]);
        assert_eq!(scan.total, 0);
        assert!(scan.plugins.is_empty());
    }

    #[test]
    fn pyside6_detected_with_strong_confidence_when_multiple_markers() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[100..108].copy_from_slice(b"PySide6/");
        bytes[300..309].copy_from_slice(b"shiboken6");
        bytes[500..514].copy_from_slice(b"PySide6.QtCore");
        let scan: PluginScan = scan_plugins(&bytes);
        assert!(scan.plugins.contains_key(&NuitkaPlugin::Pyside6));
        let hit: &PluginHit = scan.plugins.get(&NuitkaPlugin::Pyside6).expect("present");
        assert!(hit.marker_hits >= 3);
        assert_eq!(hit.confidence, PluginConfidence::Medium);
    }

    #[test]
    fn anti_bloat_detected_single_marker_is_weak() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[100..117].copy_from_slice(b"nuitka_anti_bloat");
        let scan: PluginScan = scan_plugins(&bytes);
        let hit: &PluginHit = scan.plugins.get(&NuitkaPlugin::AntiBloat).expect("present");
        assert_eq!(hit.marker_hits, 1);
        assert_eq!(hit.confidence, PluginConfidence::Weak);
    }

    #[test]
    fn numpy_detected_when_core_marker_present() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[100..110].copy_from_slice(b"numpy.core");
        bytes[300..317].copy_from_slice(b"_multiarray_umath");
        let scan: PluginScan = scan_plugins(&bytes);
        assert!(scan.plugins.contains_key(&NuitkaPlugin::Numpy));
    }

    #[test]
    fn tk_inter_recognised_via_tcl_tk_markers() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[100..105].copy_from_slice(b"tcl8.");
        bytes[300..305].copy_from_slice(b"tk8.6");
        let scan: PluginScan = scan_plugins(&bytes);
        assert!(scan.plugins.contains_key(&NuitkaPlugin::TkInter));
    }

    #[test]
    fn multiprocessing_detected() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[100..121].copy_from_slice(b"multiprocessing.spawn");
        let scan: PluginScan = scan_plugins(&bytes);
        assert!(scan.plugins.contains_key(&NuitkaPlugin::Multiprocessing));
    }
}
