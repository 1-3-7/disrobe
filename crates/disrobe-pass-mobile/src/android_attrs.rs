#[must_use]
pub fn framework_attr_name(id: u32) -> Option<&'static str> {
    if id >> 24 != 0x01 || (id >> 16) & 0xff != 0x01 {
        return None;
    }
    let entry: u16 = (id & 0xffff) as u16;
    FRAMEWORK_ATTRS
        .binary_search_by_key(&entry, |(e, _): &(u16, &str)| *e)
        .ok()
        .map(|i: usize| FRAMEWORK_ATTRS[i].1)
}

const FRAMEWORK_ATTRS: &[(u16, &str)] = &[
    (0x0000, "theme"),
    (0x0001, "label"),
    (0x0002, "icon"),
    (0x0003, "name"),
    (0x0004, "manageSpaceActivity"),
    (0x0005, "allowClearUserData"),
    (0x0006, "permission"),
    (0x0007, "readPermission"),
    (0x0008, "writePermission"),
    (0x0009, "protectionLevel"),
    (0x000a, "permissionGroup"),
    (0x000b, "sharedUserId"),
    (0x000c, "hasCode"),
    (0x000d, "persistent"),
    (0x000e, "enabled"),
    (0x000f, "debuggable"),
    (0x0010, "exported"),
    (0x0011, "process"),
    (0x0012, "taskAffinity"),
    (0x0013, "multiprocess"),
    (0x0014, "finishOnTaskLaunch"),
    (0x0015, "clearTaskOnLaunch"),
    (0x0016, "stateNotNeeded"),
    (0x0017, "excludeFromRecents"),
    (0x0018, "authorities"),
    (0x0019, "syncable"),
    (0x001a, "initOrder"),
    (0x001b, "grantUriPermissions"),
    (0x001c, "priority"),
    (0x001d, "launchMode"),
    (0x001e, "screenOrientation"),
    (0x001f, "configChanges"),
    (0x0020, "description"),
    (0x0021, "targetPackage"),
    (0x0022, "handleProfiling"),
    (0x0023, "functionalTest"),
    (0x0024, "value"),
    (0x0025, "resource"),
    (0x0026, "mimeType"),
    (0x0027, "scheme"),
    (0x0028, "host"),
    (0x0029, "port"),
    (0x002a, "path"),
    (0x002b, "pathPrefix"),
    (0x002c, "pathPattern"),
    (0x002d, "action"),
    (0x002e, "data"),
    (0x002f, "targetClass"),
    (0x020c, "minSdkVersion"),
    (0x021b, "versionCode"),
    (0x021c, "versionName"),
    (0x022b, "windowSoftInputMode"),
    (0x0270, "targetSdkVersion"),
    (0x0271, "maxSdkVersion"),
    (0x0280, "allowBackup"),
    (0x028e, "required"),
    (0x0572, "compileSdkVersion"),
    (0x0573, "compileSdkVersionCodename"),
    (0x057a, "appComponentFactory"),
    (0x063e, "dataExtractionRules"),
];

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn aapt2_verified_attr_ids_resolve() {
        assert_eq!(framework_attr_name(0x0101_0000), Some("theme"));
        assert_eq!(framework_attr_name(0x0101_0001), Some("label"));
        assert_eq!(framework_attr_name(0x0101_0002), Some("icon"));
        assert_eq!(framework_attr_name(0x0101_0003), Some("name"));
        assert_eq!(framework_attr_name(0x0101_000c), Some("hasCode"));
        assert_eq!(framework_attr_name(0x0101_000f), Some("debuggable"));
        assert_eq!(framework_attr_name(0x0101_0010), Some("exported"));
        assert_eq!(framework_attr_name(0x0101_001f), Some("configChanges"));
        assert_eq!(framework_attr_name(0x0101_020c), Some("minSdkVersion"));
        assert_eq!(framework_attr_name(0x0101_021b), Some("versionCode"));
        assert_eq!(framework_attr_name(0x0101_021c), Some("versionName"));
        assert_eq!(
            framework_attr_name(0x0101_022b),
            Some("windowSoftInputMode")
        );
        assert_eq!(framework_attr_name(0x0101_0270), Some("targetSdkVersion"));
        assert_eq!(framework_attr_name(0x0101_0271), Some("maxSdkVersion"));
        assert_eq!(framework_attr_name(0x0101_0280), Some("allowBackup"));
        assert_eq!(framework_attr_name(0x0101_028e), Some("required"));
        assert_eq!(framework_attr_name(0x0101_0572), Some("compileSdkVersion"));
        assert_eq!(
            framework_attr_name(0x0101_0573),
            Some("compileSdkVersionCodename")
        );
        assert_eq!(
            framework_attr_name(0x0101_057a),
            Some("appComponentFactory")
        );
        assert_eq!(
            framework_attr_name(0x0101_063e),
            Some("dataExtractionRules")
        );
    }

    #[test]
    fn non_framework_ids_reject() {
        assert_eq!(framework_attr_name(0x7f03_0000), None);
        assert_eq!(framework_attr_name(0x0102_0000), None);
        assert_eq!(framework_attr_name(0xffff_ffff), None);
    }

    #[test]
    fn table_is_sorted_for_binary_search() {
        for w in FRAMEWORK_ATTRS.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "table must be strictly ascending: {:#06x} then {:#06x}",
                w[0].0,
                w[1].0
            );
        }
    }
}
