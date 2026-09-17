use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DelphiOrigin {
    RuntimeLibrary,
    Author,
    Unattributed,
}

impl DelphiOrigin {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RuntimeLibrary => "Delphi RTL, VCL or FMX unit",
            Self::Author => "unit not in the known runtime library set",
            Self::Unattributed => "no unit name recovered",
        }
    }
}

const LIBRARY_SCOPES: &[&str] = &[
    "System.",
    "Vcl.",
    "Winapi.",
    "Data.",
    "Datasnap.",
    "Soap.",
    "Xml.",
    "Web.",
    "Bde.",
    "FireDAC.",
    "FMX.",
    "IBX.",
    "Posix.",
    "REST.",
    "Bluetooth.",
    "IPPeerAPI.",
    "IPPeerClient.",
    "IPPeerServer.",
];

const LIBRARY_UNITS: &[&str] = &[
    "activex",
    "actnctrls",
    "actnlist",
    "actnman",
    "actnmenus",
    "actnpopup",
    "actnres",
    "adodb",
    "appevnts",
    "axctrls",
    "bdeconst",
    "buttons",
    "checklst",
    "classes",
    "clipbrd",
    "colorgrd",
    "comconst",
    "comctrls",
    "comobj",
    "comserv",
    "comstrs",
    "consts",
    "contnrs",
    "controls",
    "convutils",
    "customizedlg",
    "db",
    "dbactns",
    "dbclient",
    "dbcommon",
    "dbconsts",
    "dbctrls",
    "dbgrids",
    "dblocal",
    "dblogdlg",
    "dbolectl",
    "dbtables",
    "ddeman",
    "dialogs",
    "dsintf",
    "extactns",
    "extctrls",
    "extdlgs",
    "filectrl",
    "forms",
    "graphics",
    "graphutil",
    "grids",
    "httpapp",
    "ibcustomdataset",
    "ibdatabase",
    "ibquery",
    "ibtable",
    "imglist",
    "inifiles",
    "jpeg",
    "listactns",
    "mask",
    "maskutils",
    "math",
    "menus",
    "messages",
    "midaslib",
    "midconst",
    "ole2",
    "olectnrs",
    "olectrls",
    "oleserver",
    "outline",
    "printers",
    "provider",
    "registry",
    "rtlconsts",
    "scktcomp",
    "shellapi",
    "shlobj",
    "sockets",
    "sqlexpr",
    "stdactnmenus",
    "stdactns",
    "stdconvs",
    "stdctrls",
    "strutils",
    "syncobjs",
    "sysconst",
    "sysinit",
    "system",
    "sysutils",
    "tabs",
    "toolwin",
    "types",
    "typinfo",
    "valedit",
    "variants",
    "varutils",
    "widestrings",
    "windows",
    "winsock",
    "winspool",
    "zlib",
];

#[cfg(test)]
pub(super) const fn library_unit_names() -> &'static [&'static str] {
    LIBRARY_UNITS
}

#[must_use]
pub fn classify_unit(unit_name: Option<&str>) -> DelphiOrigin {
    let Some(name): Option<&str> = unit_name else {
        return DelphiOrigin::Unattributed;
    };
    if name.is_empty() {
        return DelphiOrigin::Unattributed;
    }
    if LIBRARY_SCOPES
        .iter()
        .any(|scope: &&str| name.starts_with(scope))
    {
        return DelphiOrigin::RuntimeLibrary;
    }
    let lowered: String = name.to_ascii_lowercase();
    if LIBRARY_UNITS.binary_search(&lowered.as_str()).is_ok() {
        return DelphiOrigin::RuntimeLibrary;
    }
    DelphiOrigin::Author
}
