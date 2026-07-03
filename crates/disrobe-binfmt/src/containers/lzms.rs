use crate::error::{Error, Result};

const LZMS_NUM_LZ_REPS: usize = 3;
const LZMS_NUM_DELTA_REPS: usize = 3;
const LZMS_NUM_LZ_REP_DECISIONS: usize = LZMS_NUM_LZ_REPS - 1;
const LZMS_NUM_DELTA_REP_DECISIONS: usize = LZMS_NUM_DELTA_REPS - 1;

const LZMS_NUM_MAIN_PROBS: usize = 16;
const LZMS_NUM_MATCH_PROBS: usize = 32;
const LZMS_NUM_LZ_PROBS: usize = 64;
const LZMS_NUM_LZ_REP_PROBS: usize = 64;
const LZMS_NUM_DELTA_PROBS: usize = 64;
const LZMS_NUM_DELTA_REP_PROBS: usize = 64;

const LZMS_PROBABILITY_BITS: u32 = 6;
const LZMS_PROBABILITY_DENOMINATOR: u32 = 1 << LZMS_PROBABILITY_BITS;
const LZMS_INITIAL_PROBABILITY: u32 = 48;
const LZMS_INITIAL_RECENT_BITS: u64 = 0x0000_0000_5555_5555;

const LZMS_NUM_LITERAL_SYMS: usize = 256;
const LZMS_NUM_LENGTH_SYMS: usize = 54;
const LZMS_NUM_DELTA_POWER_SYMS: usize = 8;
const LZMS_MAX_NUM_OFFSET_SYMS: usize = 799;

const LZMS_LITERAL_CODE_REBUILD_FREQ: u32 = 1024;
const LZMS_LZ_OFFSET_CODE_REBUILD_FREQ: u32 = 1024;
const LZMS_LENGTH_CODE_REBUILD_FREQ: u32 = 512;
const LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ: u32 = 1024;
const LZMS_DELTA_POWER_CODE_REBUILD_FREQ: u32 = 512;

const LZMS_MAX_CODEWORD_LENGTH: u32 = 15;

const LZMS_X86_ID_WINDOW_SIZE: i32 = 65535;
const LZMS_X86_MAX_TRANSLATION_OFFSET: i32 = 1023;

const NUM_SYMBOL_BITS: u32 = 10;
const SYMBOL_MASK: u32 = (1 << NUM_SYMBOL_BITS) - 1;
const FREQ_MASK: u32 = !SYMBOL_MASK;

const LZMS_OFFSET_SLOT_BASE: [u32; LZMS_MAX_NUM_OFFSET_SYMS + 1] = [
    0x0000_0001,
    0x0000_0002,
    0x0000_0003,
    0x0000_0004,
    0x0000_0005,
    0x0000_0006,
    0x0000_0007,
    0x0000_0008,
    0x0000_0009,
    0x0000_000d,
    0x0000_0011,
    0x0000_0015,
    0x0000_0019,
    0x0000_001d,
    0x0000_0021,
    0x0000_0025,
    0x0000_0029,
    0x0000_002d,
    0x0000_0035,
    0x0000_003d,
    0x0000_0045,
    0x0000_004d,
    0x0000_0055,
    0x0000_005d,
    0x0000_0065,
    0x0000_0075,
    0x0000_0085,
    0x0000_0095,
    0x0000_00a5,
    0x0000_00b5,
    0x0000_00c5,
    0x0000_00d5,
    0x0000_00e5,
    0x0000_00f5,
    0x0000_0105,
    0x0000_0125,
    0x0000_0145,
    0x0000_0165,
    0x0000_0185,
    0x0000_01a5,
    0x0000_01c5,
    0x0000_01e5,
    0x0000_0205,
    0x0000_0225,
    0x0000_0245,
    0x0000_0265,
    0x0000_0285,
    0x0000_02a5,
    0x0000_02c5,
    0x0000_02e5,
    0x0000_0325,
    0x0000_0365,
    0x0000_03a5,
    0x0000_03e5,
    0x0000_0425,
    0x0000_0465,
    0x0000_04a5,
    0x0000_04e5,
    0x0000_0525,
    0x0000_0565,
    0x0000_05a5,
    0x0000_05e5,
    0x0000_0625,
    0x0000_0665,
    0x0000_06a5,
    0x0000_0725,
    0x0000_07a5,
    0x0000_0825,
    0x0000_08a5,
    0x0000_0925,
    0x0000_09a5,
    0x0000_0a25,
    0x0000_0aa5,
    0x0000_0b25,
    0x0000_0ba5,
    0x0000_0c25,
    0x0000_0ca5,
    0x0000_0d25,
    0x0000_0da5,
    0x0000_0e25,
    0x0000_0ea5,
    0x0000_0f25,
    0x0000_0fa5,
    0x0000_1025,
    0x0000_10a5,
    0x0000_11a5,
    0x0000_12a5,
    0x0000_13a5,
    0x0000_14a5,
    0x0000_15a5,
    0x0000_16a5,
    0x0000_17a5,
    0x0000_18a5,
    0x0000_19a5,
    0x0000_1aa5,
    0x0000_1ba5,
    0x0000_1ca5,
    0x0000_1da5,
    0x0000_1ea5,
    0x0000_1fa5,
    0x0000_20a5,
    0x0000_21a5,
    0x0000_22a5,
    0x0000_23a5,
    0x0000_24a5,
    0x0000_26a5,
    0x0000_28a5,
    0x0000_2aa5,
    0x0000_2ca5,
    0x0000_2ea5,
    0x0000_30a5,
    0x0000_32a5,
    0x0000_34a5,
    0x0000_36a5,
    0x0000_38a5,
    0x0000_3aa5,
    0x0000_3ca5,
    0x0000_3ea5,
    0x0000_40a5,
    0x0000_42a5,
    0x0000_44a5,
    0x0000_46a5,
    0x0000_48a5,
    0x0000_4aa5,
    0x0000_4ca5,
    0x0000_4ea5,
    0x0000_50a5,
    0x0000_52a5,
    0x0000_54a5,
    0x0000_56a5,
    0x0000_58a5,
    0x0000_5aa5,
    0x0000_5ca5,
    0x0000_5ea5,
    0x0000_60a5,
    0x0000_64a5,
    0x0000_68a5,
    0x0000_6ca5,
    0x0000_70a5,
    0x0000_74a5,
    0x0000_78a5,
    0x0000_7ca5,
    0x0000_80a5,
    0x0000_84a5,
    0x0000_88a5,
    0x0000_8ca5,
    0x0000_90a5,
    0x0000_94a5,
    0x0000_98a5,
    0x0000_9ca5,
    0x0000_a0a5,
    0x0000_a4a5,
    0x0000_a8a5,
    0x0000_aca5,
    0x0000_b0a5,
    0x0000_b4a5,
    0x0000_b8a5,
    0x0000_bca5,
    0x0000_c0a5,
    0x0000_c4a5,
    0x0000_c8a5,
    0x0000_cca5,
    0x0000_d0a5,
    0x0000_d4a5,
    0x0000_d8a5,
    0x0000_dca5,
    0x0000_e0a5,
    0x0000_e4a5,
    0x0000_eca5,
    0x0000_f4a5,
    0x0000_fca5,
    0x0001_04a5,
    0x0001_0ca5,
    0x0001_14a5,
    0x0001_1ca5,
    0x0001_24a5,
    0x0001_2ca5,
    0x0001_34a5,
    0x0001_3ca5,
    0x0001_44a5,
    0x0001_4ca5,
    0x0001_54a5,
    0x0001_5ca5,
    0x0001_64a5,
    0x0001_6ca5,
    0x0001_74a5,
    0x0001_7ca5,
    0x0001_84a5,
    0x0001_8ca5,
    0x0001_94a5,
    0x0001_9ca5,
    0x0001_a4a5,
    0x0001_aca5,
    0x0001_b4a5,
    0x0001_bca5,
    0x0001_c4a5,
    0x0001_cca5,
    0x0001_d4a5,
    0x0001_dca5,
    0x0001_e4a5,
    0x0001_eca5,
    0x0001_f4a5,
    0x0001_fca5,
    0x0002_04a5,
    0x0002_0ca5,
    0x0002_14a5,
    0x0002_1ca5,
    0x0002_24a5,
    0x0002_34a5,
    0x0002_44a5,
    0x0002_54a5,
    0x0002_64a5,
    0x0002_74a5,
    0x0002_84a5,
    0x0002_94a5,
    0x0002_a4a5,
    0x0002_b4a5,
    0x0002_c4a5,
    0x0002_d4a5,
    0x0002_e4a5,
    0x0002_f4a5,
    0x0003_04a5,
    0x0003_14a5,
    0x0003_24a5,
    0x0003_34a5,
    0x0003_44a5,
    0x0003_54a5,
    0x0003_64a5,
    0x0003_74a5,
    0x0003_84a5,
    0x0003_94a5,
    0x0003_a4a5,
    0x0003_b4a5,
    0x0003_c4a5,
    0x0003_d4a5,
    0x0003_e4a5,
    0x0003_f4a5,
    0x0004_04a5,
    0x0004_14a5,
    0x0004_24a5,
    0x0004_34a5,
    0x0004_44a5,
    0x0004_54a5,
    0x0004_64a5,
    0x0004_74a5,
    0x0004_84a5,
    0x0004_94a5,
    0x0004_a4a5,
    0x0004_b4a5,
    0x0004_c4a5,
    0x0004_e4a5,
    0x0005_04a5,
    0x0005_24a5,
    0x0005_44a5,
    0x0005_64a5,
    0x0005_84a5,
    0x0005_a4a5,
    0x0005_c4a5,
    0x0005_e4a5,
    0x0006_04a5,
    0x0006_24a5,
    0x0006_44a5,
    0x0006_64a5,
    0x0006_84a5,
    0x0006_a4a5,
    0x0006_c4a5,
    0x0006_e4a5,
    0x0007_04a5,
    0x0007_24a5,
    0x0007_44a5,
    0x0007_64a5,
    0x0007_84a5,
    0x0007_a4a5,
    0x0007_c4a5,
    0x0007_e4a5,
    0x0008_04a5,
    0x0008_24a5,
    0x0008_44a5,
    0x0008_64a5,
    0x0008_84a5,
    0x0008_a4a5,
    0x0008_c4a5,
    0x0008_e4a5,
    0x0009_04a5,
    0x0009_24a5,
    0x0009_44a5,
    0x0009_64a5,
    0x0009_84a5,
    0x0009_a4a5,
    0x0009_c4a5,
    0x0009_e4a5,
    0x000a_04a5,
    0x000a_24a5,
    0x000a_44a5,
    0x000a_64a5,
    0x000a_a4a5,
    0x000a_e4a5,
    0x000b_24a5,
    0x000b_64a5,
    0x000b_a4a5,
    0x000b_e4a5,
    0x000c_24a5,
    0x000c_64a5,
    0x000c_a4a5,
    0x000c_e4a5,
    0x000d_24a5,
    0x000d_64a5,
    0x000d_a4a5,
    0x000d_e4a5,
    0x000e_24a5,
    0x000e_64a5,
    0x000e_a4a5,
    0x000e_e4a5,
    0x000f_24a5,
    0x000f_64a5,
    0x000f_a4a5,
    0x000f_e4a5,
    0x0010_24a5,
    0x0010_64a5,
    0x0010_a4a5,
    0x0010_e4a5,
    0x0011_24a5,
    0x0011_64a5,
    0x0011_a4a5,
    0x0011_e4a5,
    0x0012_24a5,
    0x0012_64a5,
    0x0012_a4a5,
    0x0012_e4a5,
    0x0013_24a5,
    0x0013_64a5,
    0x0013_a4a5,
    0x0013_e4a5,
    0x0014_24a5,
    0x0014_64a5,
    0x0014_a4a5,
    0x0014_e4a5,
    0x0015_24a5,
    0x0015_64a5,
    0x0015_a4a5,
    0x0015_e4a5,
    0x0016_24a5,
    0x0016_64a5,
    0x0016_a4a5,
    0x0016_e4a5,
    0x0017_24a5,
    0x0017_64a5,
    0x0017_a4a5,
    0x0017_e4a5,
    0x0018_24a5,
    0x0018_64a5,
    0x0018_a4a5,
    0x0018_e4a5,
    0x0019_24a5,
    0x0019_64a5,
    0x0019_e4a5,
    0x001a_64a5,
    0x001a_e4a5,
    0x001b_64a5,
    0x001b_e4a5,
    0x001c_64a5,
    0x001c_e4a5,
    0x001d_64a5,
    0x001d_e4a5,
    0x001e_64a5,
    0x001e_e4a5,
    0x001f_64a5,
    0x001f_e4a5,
    0x0020_64a5,
    0x0020_e4a5,
    0x0021_64a5,
    0x0021_e4a5,
    0x0022_64a5,
    0x0022_e4a5,
    0x0023_64a5,
    0x0023_e4a5,
    0x0024_64a5,
    0x0024_e4a5,
    0x0025_64a5,
    0x0025_e4a5,
    0x0026_64a5,
    0x0026_e4a5,
    0x0027_64a5,
    0x0027_e4a5,
    0x0028_64a5,
    0x0028_e4a5,
    0x0029_64a5,
    0x0029_e4a5,
    0x002a_64a5,
    0x002a_e4a5,
    0x002b_64a5,
    0x002b_e4a5,
    0x002c_64a5,
    0x002c_e4a5,
    0x002d_64a5,
    0x002d_e4a5,
    0x002e_64a5,
    0x002e_e4a5,
    0x002f_64a5,
    0x002f_e4a5,
    0x0030_64a5,
    0x0030_e4a5,
    0x0031_64a5,
    0x0031_e4a5,
    0x0032_64a5,
    0x0032_e4a5,
    0x0033_64a5,
    0x0033_e4a5,
    0x0034_64a5,
    0x0034_e4a5,
    0x0035_64a5,
    0x0035_e4a5,
    0x0036_64a5,
    0x0036_e4a5,
    0x0037_64a5,
    0x0037_e4a5,
    0x0038_64a5,
    0x0038_e4a5,
    0x0039_64a5,
    0x0039_e4a5,
    0x003a_64a5,
    0x003a_e4a5,
    0x003b_64a5,
    0x003b_e4a5,
    0x003c_64a5,
    0x003c_e4a5,
    0x003d_64a5,
    0x003d_e4a5,
    0x003e_e4a5,
    0x003f_e4a5,
    0x0040_e4a5,
    0x0041_e4a5,
    0x0042_e4a5,
    0x0043_e4a5,
    0x0044_e4a5,
    0x0045_e4a5,
    0x0046_e4a5,
    0x0047_e4a5,
    0x0048_e4a5,
    0x0049_e4a5,
    0x004a_e4a5,
    0x004b_e4a5,
    0x004c_e4a5,
    0x004d_e4a5,
    0x004e_e4a5,
    0x004f_e4a5,
    0x0050_e4a5,
    0x0051_e4a5,
    0x0052_e4a5,
    0x0053_e4a5,
    0x0054_e4a5,
    0x0055_e4a5,
    0x0056_e4a5,
    0x0057_e4a5,
    0x0058_e4a5,
    0x0059_e4a5,
    0x005a_e4a5,
    0x005b_e4a5,
    0x005c_e4a5,
    0x005d_e4a5,
    0x005e_e4a5,
    0x005f_e4a5,
    0x0060_e4a5,
    0x0061_e4a5,
    0x0062_e4a5,
    0x0063_e4a5,
    0x0064_e4a5,
    0x0065_e4a5,
    0x0066_e4a5,
    0x0067_e4a5,
    0x0068_e4a5,
    0x0069_e4a5,
    0x006a_e4a5,
    0x006b_e4a5,
    0x006c_e4a5,
    0x006d_e4a5,
    0x006e_e4a5,
    0x006f_e4a5,
    0x0070_e4a5,
    0x0071_e4a5,
    0x0072_e4a5,
    0x0073_e4a5,
    0x0074_e4a5,
    0x0075_e4a5,
    0x0076_e4a5,
    0x0077_e4a5,
    0x0078_e4a5,
    0x0079_e4a5,
    0x007a_e4a5,
    0x007b_e4a5,
    0x007c_e4a5,
    0x007d_e4a5,
    0x007e_e4a5,
    0x007f_e4a5,
    0x0080_e4a5,
    0x0081_e4a5,
    0x0082_e4a5,
    0x0083_e4a5,
    0x0084_e4a5,
    0x0085_e4a5,
    0x0086_e4a5,
    0x0087_e4a5,
    0x0088_e4a5,
    0x0089_e4a5,
    0x008a_e4a5,
    0x008b_e4a5,
    0x008c_e4a5,
    0x008d_e4a5,
    0x008f_e4a5,
    0x0091_e4a5,
    0x0093_e4a5,
    0x0095_e4a5,
    0x0097_e4a5,
    0x0099_e4a5,
    0x009b_e4a5,
    0x009d_e4a5,
    0x009f_e4a5,
    0x00a1_e4a5,
    0x00a3_e4a5,
    0x00a5_e4a5,
    0x00a7_e4a5,
    0x00a9_e4a5,
    0x00ab_e4a5,
    0x00ad_e4a5,
    0x00af_e4a5,
    0x00b1_e4a5,
    0x00b3_e4a5,
    0x00b5_e4a5,
    0x00b7_e4a5,
    0x00b9_e4a5,
    0x00bb_e4a5,
    0x00bd_e4a5,
    0x00bf_e4a5,
    0x00c1_e4a5,
    0x00c3_e4a5,
    0x00c5_e4a5,
    0x00c7_e4a5,
    0x00c9_e4a5,
    0x00cb_e4a5,
    0x00cd_e4a5,
    0x00cf_e4a5,
    0x00d1_e4a5,
    0x00d3_e4a5,
    0x00d5_e4a5,
    0x00d7_e4a5,
    0x00d9_e4a5,
    0x00db_e4a5,
    0x00dd_e4a5,
    0x00df_e4a5,
    0x00e1_e4a5,
    0x00e3_e4a5,
    0x00e5_e4a5,
    0x00e7_e4a5,
    0x00e9_e4a5,
    0x00eb_e4a5,
    0x00ed_e4a5,
    0x00ef_e4a5,
    0x00f1_e4a5,
    0x00f3_e4a5,
    0x00f5_e4a5,
    0x00f7_e4a5,
    0x00f9_e4a5,
    0x00fb_e4a5,
    0x00fd_e4a5,
    0x00ff_e4a5,
    0x0101_e4a5,
    0x0103_e4a5,
    0x0105_e4a5,
    0x0107_e4a5,
    0x0109_e4a5,
    0x010b_e4a5,
    0x010d_e4a5,
    0x010f_e4a5,
    0x0111_e4a5,
    0x0113_e4a5,
    0x0115_e4a5,
    0x0117_e4a5,
    0x0119_e4a5,
    0x011b_e4a5,
    0x011d_e4a5,
    0x011f_e4a5,
    0x0121_e4a5,
    0x0123_e4a5,
    0x0125_e4a5,
    0x0127_e4a5,
    0x0129_e4a5,
    0x012b_e4a5,
    0x012d_e4a5,
    0x012f_e4a5,
    0x0131_e4a5,
    0x0133_e4a5,
    0x0135_e4a5,
    0x0137_e4a5,
    0x013b_e4a5,
    0x013f_e4a5,
    0x0143_e4a5,
    0x0147_e4a5,
    0x014b_e4a5,
    0x014f_e4a5,
    0x0153_e4a5,
    0x0157_e4a5,
    0x015b_e4a5,
    0x015f_e4a5,
    0x0163_e4a5,
    0x0167_e4a5,
    0x016b_e4a5,
    0x016f_e4a5,
    0x0173_e4a5,
    0x0177_e4a5,
    0x017b_e4a5,
    0x017f_e4a5,
    0x0183_e4a5,
    0x0187_e4a5,
    0x018b_e4a5,
    0x018f_e4a5,
    0x0193_e4a5,
    0x0197_e4a5,
    0x019b_e4a5,
    0x019f_e4a5,
    0x01a3_e4a5,
    0x01a7_e4a5,
    0x01ab_e4a5,
    0x01af_e4a5,
    0x01b3_e4a5,
    0x01b7_e4a5,
    0x01bb_e4a5,
    0x01bf_e4a5,
    0x01c3_e4a5,
    0x01c7_e4a5,
    0x01cb_e4a5,
    0x01cf_e4a5,
    0x01d3_e4a5,
    0x01d7_e4a5,
    0x01db_e4a5,
    0x01df_e4a5,
    0x01e3_e4a5,
    0x01e7_e4a5,
    0x01eb_e4a5,
    0x01ef_e4a5,
    0x01f3_e4a5,
    0x01f7_e4a5,
    0x01fb_e4a5,
    0x01ff_e4a5,
    0x0203_e4a5,
    0x0207_e4a5,
    0x020b_e4a5,
    0x020f_e4a5,
    0x0213_e4a5,
    0x0217_e4a5,
    0x021b_e4a5,
    0x021f_e4a5,
    0x0223_e4a5,
    0x0227_e4a5,
    0x022b_e4a5,
    0x022f_e4a5,
    0x0233_e4a5,
    0x0237_e4a5,
    0x023b_e4a5,
    0x023f_e4a5,
    0x0243_e4a5,
    0x0247_e4a5,
    0x024b_e4a5,
    0x024f_e4a5,
    0x0253_e4a5,
    0x0257_e4a5,
    0x025b_e4a5,
    0x025f_e4a5,
    0x0263_e4a5,
    0x0267_e4a5,
    0x026b_e4a5,
    0x026f_e4a5,
    0x0273_e4a5,
    0x0277_e4a5,
    0x027b_e4a5,
    0x027f_e4a5,
    0x0283_e4a5,
    0x0287_e4a5,
    0x028b_e4a5,
    0x028f_e4a5,
    0x0293_e4a5,
    0x0297_e4a5,
    0x029b_e4a5,
    0x029f_e4a5,
    0x02a3_e4a5,
    0x02a7_e4a5,
    0x02ab_e4a5,
    0x02af_e4a5,
    0x02b3_e4a5,
    0x02bb_e4a5,
    0x02c3_e4a5,
    0x02cb_e4a5,
    0x02d3_e4a5,
    0x02db_e4a5,
    0x02e3_e4a5,
    0x02eb_e4a5,
    0x02f3_e4a5,
    0x02fb_e4a5,
    0x0303_e4a5,
    0x030b_e4a5,
    0x0313_e4a5,
    0x031b_e4a5,
    0x0323_e4a5,
    0x032b_e4a5,
    0x0333_e4a5,
    0x033b_e4a5,
    0x0343_e4a5,
    0x034b_e4a5,
    0x0353_e4a5,
    0x035b_e4a5,
    0x0363_e4a5,
    0x036b_e4a5,
    0x0373_e4a5,
    0x037b_e4a5,
    0x0383_e4a5,
    0x038b_e4a5,
    0x0393_e4a5,
    0x039b_e4a5,
    0x03a3_e4a5,
    0x03ab_e4a5,
    0x03b3_e4a5,
    0x03bb_e4a5,
    0x03c3_e4a5,
    0x03cb_e4a5,
    0x03d3_e4a5,
    0x03db_e4a5,
    0x03e3_e4a5,
    0x03eb_e4a5,
    0x03f3_e4a5,
    0x03fb_e4a5,
    0x0403_e4a5,
    0x040b_e4a5,
    0x0413_e4a5,
    0x041b_e4a5,
    0x0423_e4a5,
    0x042b_e4a5,
    0x0433_e4a5,
    0x043b_e4a5,
    0x0443_e4a5,
    0x044b_e4a5,
    0x0453_e4a5,
    0x045b_e4a5,
    0x0463_e4a5,
    0x046b_e4a5,
    0x0473_e4a5,
    0x047b_e4a5,
    0x0483_e4a5,
    0x048b_e4a5,
    0x0493_e4a5,
    0x049b_e4a5,
    0x04a3_e4a5,
    0x04ab_e4a5,
    0x04b3_e4a5,
    0x04bb_e4a5,
    0x04c3_e4a5,
    0x04cb_e4a5,
    0x04d3_e4a5,
    0x04db_e4a5,
    0x04e3_e4a5,
    0x04eb_e4a5,
    0x04f3_e4a5,
    0x04fb_e4a5,
    0x0503_e4a5,
    0x050b_e4a5,
    0x0513_e4a5,
    0x051b_e4a5,
    0x0523_e4a5,
    0x052b_e4a5,
    0x0533_e4a5,
    0x053b_e4a5,
    0x0543_e4a5,
    0x054b_e4a5,
    0x0553_e4a5,
    0x055b_e4a5,
    0x0563_e4a5,
    0x056b_e4a5,
    0x0573_e4a5,
    0x057b_e4a5,
    0x0583_e4a5,
    0x058b_e4a5,
    0x0593_e4a5,
    0x059b_e4a5,
    0x05a3_e4a5,
    0x05ab_e4a5,
    0x05b3_e4a5,
    0x05bb_e4a5,
    0x05c3_e4a5,
    0x05cb_e4a5,
    0x05d3_e4a5,
    0x05db_e4a5,
    0x05e3_e4a5,
    0x05eb_e4a5,
    0x05f3_e4a5,
    0x05fb_e4a5,
    0x060b_e4a5,
    0x061b_e4a5,
    0x062b_e4a5,
    0x063b_e4a5,
    0x064b_e4a5,
    0x065b_e4a5,
    0x465b_e4a5,
];

const LZMS_EXTRA_OFFSET_BITS: [u8; LZMS_MAX_NUM_OFFSET_SYMS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 30,
];

const LZMS_LENGTH_SLOT_BASE: [u32; LZMS_NUM_LENGTH_SYMS + 1] = [
    0x0000_0001,
    0x0000_0002,
    0x0000_0003,
    0x0000_0004,
    0x0000_0005,
    0x0000_0006,
    0x0000_0007,
    0x0000_0008,
    0x0000_0009,
    0x0000_000a,
    0x0000_000b,
    0x0000_000c,
    0x0000_000d,
    0x0000_000e,
    0x0000_000f,
    0x0000_0010,
    0x0000_0011,
    0x0000_0012,
    0x0000_0013,
    0x0000_0014,
    0x0000_0015,
    0x0000_0016,
    0x0000_0017,
    0x0000_0018,
    0x0000_0019,
    0x0000_001a,
    0x0000_001b,
    0x0000_001d,
    0x0000_001f,
    0x0000_0021,
    0x0000_0023,
    0x0000_0027,
    0x0000_002b,
    0x0000_002f,
    0x0000_0033,
    0x0000_0037,
    0x0000_003b,
    0x0000_0043,
    0x0000_004b,
    0x0000_0053,
    0x0000_005b,
    0x0000_006b,
    0x0000_007b,
    0x0000_008b,
    0x0000_009b,
    0x0000_00ab,
    0x0000_00cb,
    0x0000_00eb,
    0x0000_012b,
    0x0000_01ab,
    0x0000_02ab,
    0x0000_04ab,
    0x0000_08ab,
    0x0001_08ab,
    0x4001_08ab,
];

const LZMS_EXTRA_LENGTH_BITS: [u8; LZMS_NUM_LENGTH_SYMS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 6, 7, 8, 9, 10, 16, 30,
];

#[derive(Debug, Clone, Copy)]
struct ProbabilityEntry {
    num_recent_zero_bits: u32,
    recent_bits: u64,
}

impl ProbabilityEntry {
    const fn init() -> Self {
        Self {
            num_recent_zero_bits: LZMS_INITIAL_PROBABILITY,
            recent_bits: LZMS_INITIAL_RECENT_BITS,
        }
    }

    const fn probability(self) -> u32 {
        let mut prob: u32 = self.num_recent_zero_bits;
        prob = prob.wrapping_add(prob.wrapping_sub(1) >> 31);
        prob -= prob >> LZMS_PROBABILITY_BITS;
        prob
    }

    const fn update(&mut self, bit: u32) {
        let high_bit: u32 = (self.recent_bits >> (LZMS_PROBABILITY_DENOMINATOR - 1)) as u32;
        let delta: i32 = high_bit as i32 - bit as i32;
        self.num_recent_zero_bits = (self.num_recent_zero_bits as i32 + delta) as u32;
        self.recent_bits = (self.recent_bits << 1) | bit as u64;
    }
}

#[derive(Debug)]
struct RangeDecoder<'a> {
    range: u32,
    code: u32,
    next: usize,
    end: usize,
    data: &'a [u8],
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        let c0: u32 = u32::from(u16::from_le_bytes([data[0], data[1]]));
        let c1: u32 = u32::from(u16::from_le_bytes([data[2], data[3]]));
        Self {
            range: 0xffff_ffff,
            code: (c0 << 16) | c1,
            next: 4,
            end: data.len(),
            data,
        }
    }

    fn decode_bit(&mut self, states: &mut [ProbabilityEntry], state_p: &mut u32) -> u32 {
        let num_states: u32 = states.len() as u32;
        let index: usize = *state_p as usize;
        *state_p = (*state_p << 1) & (num_states - 1);
        let prob: u32 = states[index].probability();
        if self.range & 0xffff_0000 == 0 {
            self.range <<= 16;
            self.code <<= 16;
            if self.next != self.end {
                let unit: u32 = u32::from(u16::from_le_bytes([
                    self.data[self.next],
                    self.data[self.next + 1],
                ]));
                self.code |= unit;
                self.next += 2;
            }
        }
        let bound: u32 = (self.range >> LZMS_PROBABILITY_BITS) * prob;
        if self.code < bound {
            self.range = bound;
            states[index].update(0);
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            states[index].update(1);
            *state_p |= 1;
            1
        }
    }
}

#[derive(Debug)]
struct InputBitstream<'a> {
    bitbuf: u64,
    bitsleft: u32,
    next: usize,
    begin: usize,
    data: &'a [u8],
}

const BITBUF_NBITS: u32 = 64;

impl<'a> InputBitstream<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            bitbuf: 0,
            bitsleft: 0,
            next: data.len(),
            begin: 0,
            data,
        }
    }

    fn ensure_bits(&mut self, num_bits: u32) {
        if self.bitsleft >= num_bits {
            return;
        }
        let avail: u32 = BITBUF_NBITS - self.bitsleft;
        if self.next != self.begin {
            self.next -= 2;
            let unit: u64 = u64::from(u16::from_le_bytes([
                self.data[self.next],
                self.data[self.next + 1],
            ]));
            self.bitbuf |= unit << (avail - 16);
        }
        if self.next != self.begin {
            self.next -= 2;
            let unit: u64 = u64::from(u16::from_le_bytes([
                self.data[self.next],
                self.data[self.next + 1],
            ]));
            self.bitbuf |= unit << (avail - 32);
        }
        self.bitsleft += 32;
    }

    const fn peek_bits(&self, num_bits: u32) -> u64 {
        if num_bits == 0 {
            return 0;
        }
        (self.bitbuf >> 1) >> (BITBUF_NBITS - num_bits - 1)
    }

    const fn remove_bits(&mut self, num_bits: u32) {
        self.bitbuf <<= num_bits;
        self.bitsleft -= num_bits;
    }

    fn read_bits(&mut self, num_bits: u32) -> u32 {
        if num_bits == 0 {
            return 0;
        }
        self.ensure_bits(num_bits);
        let bits: u64 = self.peek_bits(num_bits);
        self.remove_bits(num_bits);
        bits as u32
    }
}

#[derive(Debug)]
struct HuffmanCode {
    rebuild_freq: u32,
    num_syms_until_rebuild: u32,
    freqs: Vec<u32>,
    lens: Vec<u8>,
    counts: Vec<u32>,
    sorted_syms: Vec<u16>,
}

impl HuffmanCode {
    fn new(num_syms: usize, rebuild_freq: u32) -> Self {
        let mut code: Self = Self {
            rebuild_freq,
            num_syms_until_rebuild: rebuild_freq,
            freqs: vec![1u32; num_syms],
            lens: vec![0u8; num_syms],
            counts: vec![0u32; (LZMS_MAX_CODEWORD_LENGTH + 1) as usize],
            sorted_syms: vec![0u16; num_syms],
        };
        code.rebuild();
        code.num_syms_until_rebuild = rebuild_freq;
        code
    }

    fn rebuild(&mut self) {
        make_canonical_lengths(&self.freqs, LZMS_MAX_CODEWORD_LENGTH, &mut self.lens);
        self.build_decode_layout();
        self.num_syms_until_rebuild = self.rebuild_freq;
    }

    fn build_decode_layout(&mut self) {
        for count in &mut self.counts {
            *count = 0;
        }
        for &len in &self.lens {
            self.counts[len as usize] += 1;
        }
        self.counts[0] = 0;
        let max_len: usize = LZMS_MAX_CODEWORD_LENGTH as usize;
        let mut offsets: Vec<u32> = vec![0u32; max_len + 2];
        for len in 1..=max_len {
            offsets[len + 1] = offsets[len] + self.counts[len];
        }
        for (sym, &len) in self.lens.iter().enumerate() {
            if len != 0 {
                let slot: u32 = offsets[len as usize];
                self.sorted_syms[slot as usize] = sym as u16;
                offsets[len as usize] += 1;
            }
        }
    }

    fn decode_symbol(&mut self, is: &mut InputBitstream<'_>) -> Result<u16> {
        let mut code: u32 = 0;
        let mut first: u32 = 0;
        let mut index: u32 = 0;
        let mut symbol: u16 = 0;
        let mut found: bool = false;
        for len in 1..=LZMS_MAX_CODEWORD_LENGTH {
            code |= is.read_bits(1);
            let count: u32 = self.counts[len as usize];
            if code < first + count {
                let slot: u32 = index + (code - first);
                symbol = *self.sorted_syms.get(slot as usize).ok_or_else(|| {
                    Error::Decompression("lzms huffman symbol slot overflow".to_owned())
                })?;
                found = true;
                break;
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        if !found {
            return Err(Error::Decompression(
                "lzms huffman code not found".to_owned(),
            ));
        }
        self.freqs[symbol as usize] += 1;
        self.num_syms_until_rebuild -= 1;
        if self.num_syms_until_rebuild == 0 {
            self.rebuild();
            for freq in &mut self.freqs {
                *freq = (*freq >> 1) + 1;
            }
        }
        Ok(symbol)
    }
}

pub(crate) fn canonical_lengths(freqs: &[u32], max_codeword_len: u32, lens: &mut [u8]) {
    make_canonical_lengths(freqs, max_codeword_len, lens);
}

fn make_canonical_lengths(freqs: &[u32], max_codeword_len: u32, lens: &mut [u8]) {
    let num_syms: usize = freqs.len();
    let mut a: Vec<u32> = vec![0u32; num_syms];
    let num_used_syms: usize = sort_symbols(freqs, lens, &mut a);
    if num_used_syms == 0 {
        return;
    }
    if num_used_syms == 1 {
        if num_syms == 1 {
            lens[0] = 1;
            return;
        }
        let sym: usize = (a[0] & SYMBOL_MASK) as usize;
        let nonzero_idx: usize = if sym != 0 { sym } else { 1 };
        lens[0] = 1;
        lens[nonzero_idx] = 1;
        return;
    }
    build_tree(&mut a, num_used_syms);
    let mut len_counts: Vec<u32> = vec![0u32; (max_codeword_len + 1) as usize];
    compute_length_counts(&mut a, num_used_syms - 2, &mut len_counts, max_codeword_len);
    assign_lengths(&a, lens, &len_counts, max_codeword_len);
}

fn sort_symbols(freqs: &[u32], lens: &mut [u8], symout: &mut [u32]) -> usize {
    let num_syms: usize = freqs.len();
    let mut keyed: Vec<u32> = Vec::with_capacity(num_syms);
    for (sym, &freq) in freqs.iter().enumerate() {
        if freq != 0 {
            keyed.push(sym as u32 | (freq << NUM_SYMBOL_BITS));
        } else {
            lens[sym] = 0;
        }
    }
    keyed.sort_unstable();
    for (i, &v) in keyed.iter().enumerate() {
        symout[i] = v;
    }
    keyed.len()
}

fn build_tree(a: &mut [u32], sym_count: usize) {
    let last_idx: usize = sym_count - 1;
    let mut i: usize = 0;
    let mut b: usize = 0;
    let mut e: usize = 0;
    loop {
        let new_freq: u32;
        if i < last_idx && (b == e || (a[i + 1] & FREQ_MASK) <= (a[b] & FREQ_MASK)) {
            new_freq = (a[i] & FREQ_MASK) + (a[i + 1] & FREQ_MASK);
            i += 2;
        } else if b + 2 <= e && (i > last_idx || (a[b + 1] & FREQ_MASK) < (a[i] & FREQ_MASK)) {
            new_freq = (a[b] & FREQ_MASK) + (a[b + 1] & FREQ_MASK);
            a[b] = ((e as u32) << NUM_SYMBOL_BITS) | (a[b] & SYMBOL_MASK);
            a[b + 1] = ((e as u32) << NUM_SYMBOL_BITS) | (a[b + 1] & SYMBOL_MASK);
            b += 2;
        } else {
            new_freq = (a[i] & FREQ_MASK) + (a[b] & FREQ_MASK);
            a[b] = ((e as u32) << NUM_SYMBOL_BITS) | (a[b] & SYMBOL_MASK);
            i += 1;
            b += 1;
        }
        a[e] = new_freq | (a[e] & SYMBOL_MASK);
        e += 1;
        if e >= last_idx {
            break;
        }
    }
}

fn compute_length_counts(a: &mut [u32], root_idx: usize, len_counts: &mut [u32], max_len: u32) {
    for count in len_counts.iter_mut() {
        *count = 0;
    }
    len_counts[1] = 2;
    a[root_idx] &= SYMBOL_MASK;
    let mut node: isize = root_idx as isize - 1;
    while node >= 0 {
        let n: usize = node as usize;
        let parent: usize = (a[n] >> NUM_SYMBOL_BITS) as usize;
        let parent_depth: u32 = a[parent] >> NUM_SYMBOL_BITS;
        let depth: u32 = parent_depth + 1;
        a[n] = (a[n] & SYMBOL_MASK) | (depth << NUM_SYMBOL_BITS);
        let mut len: u32 = depth;
        if len >= max_len {
            len = max_len;
            while len_counts[len as usize] == 0 {
                len -= 1;
            }
        }
        len_counts[len as usize] -= 1;
        len_counts[(len + 1) as usize] += 2;
        node -= 1;
    }
}

fn assign_lengths(a: &[u32], lens: &mut [u8], len_counts: &[u32], max_len: u32) {
    let mut i: usize = 0;
    let mut len: u32 = max_len;
    while len >= 1 {
        let mut count: u32 = len_counts[len as usize];
        while count > 0 {
            lens[(a[i] & SYMBOL_MASK) as usize] = len as u8;
            i += 1;
            count -= 1;
        }
        len -= 1;
    }
}

fn get_offset_slot(offset: u32) -> usize {
    get_slot(offset, &LZMS_OFFSET_SLOT_BASE, LZMS_MAX_NUM_OFFSET_SYMS)
}

fn get_slot(value: u32, slot_base_tab: &[u32], num_slots: usize) -> usize {
    let mut l: usize = 0;
    let mut r: usize = num_slots - 1;
    loop {
        let slot: usize = usize::midpoint(l, r);
        if value >= slot_base_tab[slot] {
            if value < slot_base_tab[slot + 1] {
                return slot;
            }
            l = slot + 1;
        } else {
            r = slot - 1;
        }
    }
}

fn get_num_offset_slots(uncompressed_size: usize) -> usize {
    if uncompressed_size < 2 {
        return 0;
    }
    1 + get_offset_slot((uncompressed_size - 1) as u32)
}

struct ProbStates {
    main: [ProbabilityEntry; LZMS_NUM_MAIN_PROBS],
    match_probs: [ProbabilityEntry; LZMS_NUM_MATCH_PROBS],
    lz: [ProbabilityEntry; LZMS_NUM_LZ_PROBS],
    delta: [ProbabilityEntry; LZMS_NUM_DELTA_PROBS],
    lz_rep: [[ProbabilityEntry; LZMS_NUM_LZ_REP_PROBS]; LZMS_NUM_LZ_REP_DECISIONS],
    delta_rep: [[ProbabilityEntry; LZMS_NUM_DELTA_REP_PROBS]; LZMS_NUM_DELTA_REP_DECISIONS],
}

impl ProbStates {
    const fn init() -> Self {
        Self {
            main: [ProbabilityEntry::init(); LZMS_NUM_MAIN_PROBS],
            match_probs: [ProbabilityEntry::init(); LZMS_NUM_MATCH_PROBS],
            lz: [ProbabilityEntry::init(); LZMS_NUM_LZ_PROBS],
            delta: [ProbabilityEntry::init(); LZMS_NUM_DELTA_PROBS],
            lz_rep: [[ProbabilityEntry::init(); LZMS_NUM_LZ_REP_PROBS]; LZMS_NUM_LZ_REP_DECISIONS],
            delta_rep: [[ProbabilityEntry::init(); LZMS_NUM_DELTA_REP_PROBS];
                LZMS_NUM_DELTA_REP_DECISIONS],
        }
    }
}

struct DecodeStates {
    main: u32,
    match_state: u32,
    lz: u32,
    delta: u32,
    lz_rep: [u32; LZMS_NUM_LZ_REP_DECISIONS],
    delta_rep: [u32; LZMS_NUM_DELTA_REP_DECISIONS],
}

impl DecodeStates {
    const fn init() -> Self {
        Self {
            main: 0,
            match_state: 0,
            lz: 0,
            delta: 0,
            lz_rep: [0u32; LZMS_NUM_LZ_REP_DECISIONS],
            delta_rep: [0u32; LZMS_NUM_DELTA_REP_DECISIONS],
        }
    }
}

struct Codes {
    literal: HuffmanCode,
    lz_offset: HuffmanCode,
    length: HuffmanCode,
    delta_offset: HuffmanCode,
    delta_power: HuffmanCode,
}

impl Codes {
    fn init(num_offset_slots: usize) -> Self {
        let offset_syms: usize = num_offset_slots.max(1);
        Self {
            literal: HuffmanCode::new(LZMS_NUM_LITERAL_SYMS, LZMS_LITERAL_CODE_REBUILD_FREQ),
            lz_offset: HuffmanCode::new(offset_syms, LZMS_LZ_OFFSET_CODE_REBUILD_FREQ),
            length: HuffmanCode::new(LZMS_NUM_LENGTH_SYMS, LZMS_LENGTH_CODE_REBUILD_FREQ),
            delta_offset: HuffmanCode::new(offset_syms, LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ),
            delta_power: HuffmanCode::new(
                LZMS_NUM_DELTA_POWER_SYMS,
                LZMS_DELTA_POWER_CODE_REBUILD_FREQ,
            ),
        }
    }
}

fn decode_lz_offset(codes: &mut Codes, is: &mut InputBitstream<'_>) -> Result<u32> {
    let slot: usize = codes.lz_offset.decode_symbol(is)? as usize;
    let base: u32 = LZMS_OFFSET_SLOT_BASE[slot];
    let extra: u32 = is.read_bits(u32::from(LZMS_EXTRA_OFFSET_BITS[slot]));
    Ok(base + extra)
}

fn decode_delta_offset(codes: &mut Codes, is: &mut InputBitstream<'_>) -> Result<u32> {
    let slot: usize = codes.delta_offset.decode_symbol(is)? as usize;
    let base: u32 = LZMS_OFFSET_SLOT_BASE[slot];
    let extra: u32 = is.read_bits(u32::from(LZMS_EXTRA_OFFSET_BITS[slot]));
    Ok(base + extra)
}

fn decode_length(codes: &mut Codes, is: &mut InputBitstream<'_>) -> Result<u32> {
    let slot: usize = codes.length.decode_symbol(is)? as usize;
    let mut length: u32 = LZMS_LENGTH_SLOT_BASE[slot];
    let num_extra: u8 = LZMS_EXTRA_LENGTH_BITS[slot];
    if num_extra != 0 {
        length += is.read_bits(u32::from(num_extra));
    }
    Ok(length)
}

fn lz_copy(out: &mut [u8], pos: usize, offset: u32, length: u32) -> Result<()> {
    let offset_usize: usize = offset as usize;
    if offset_usize == 0 || offset_usize > pos {
        return Err(Error::Decompression(
            "lzms lz offset escapes output window".to_owned(),
        ));
    }
    let end: usize = pos
        .checked_add(length as usize)
        .ok_or_else(|| Error::Decompression("lzms lz length overflow".to_owned()))?;
    if end > out.len() {
        return Err(Error::Decompression(
            "lzms lz match overruns output".to_owned(),
        ));
    }
    let mut src: usize = pos - offset_usize;
    let mut dst: usize = pos;
    while dst < end {
        out[dst] = out[src];
        src += 1;
        dst += 1;
    }
    Ok(())
}

/// Decompress a raw LZMS-compressed chunk to its known uncompressed size.
///
/// The format and algorithm follow the publicly documented LZMS codec used by
/// the Windows 8 compression API (`COMPRESS_ALGORITHM_LZMS | COMPRESS_RAW`) and
/// in WIM/CAB containers: an LZ77 backend with binary range-coded item-type
/// decisions read forwards and adaptive-Huffman symbols read backwards, with an
/// x86 absolute-to-relative call/jump post-filter.
pub fn lzms_decompress(input: &[u8], out_size: usize) -> Result<Vec<u8>> {
    if input.len() & 1 != 0 || input.len() < 4 {
        return Err(Error::Decompression(
            "lzms compressed chunk has odd length or is too short".to_owned(),
        ));
    }
    let mut out: Vec<u8> = vec![0u8; out_size];
    if out_size == 0 {
        return Ok(out);
    }
    let mut rd: RangeDecoder<'_> = RangeDecoder::new(input);
    let mut is: InputBitstream<'_> = InputBitstream::new(input);
    let mut probs: ProbStates = ProbStates::init();
    let mut states: DecodeStates = DecodeStates::init();
    let mut codes: Codes = Codes::init(get_num_offset_slots(out_size));

    let mut recent_lz_offsets: [u32; LZMS_NUM_LZ_REPS + 1] = [1, 2, 3, 4];
    let mut recent_delta_pairs: [u64; LZMS_NUM_DELTA_REPS + 1] = [1, 2, 3, 4];
    let mut prev_item_type: u32 = 0;

    let mut pos: usize = 0;
    while pos < out_size {
        if rd.decode_bit(&mut probs.main, &mut states.main) == 0 {
            let sym: u16 = codes.literal.decode_symbol(&mut is)?;
            out[pos] = sym as u8;
            pos += 1;
            prev_item_type = 0;
        } else if rd.decode_bit(&mut probs.match_probs, &mut states.match_state) == 0 {
            let offset: u32;
            if rd.decode_bit(&mut probs.lz, &mut states.lz) == 0 {
                offset = decode_lz_offset(&mut codes, &mut is)?;
                recent_lz_offsets[3] = recent_lz_offsets[2];
                recent_lz_offsets[2] = recent_lz_offsets[1];
                recent_lz_offsets[1] = recent_lz_offsets[0];
            } else if rd.decode_bit(&mut probs.lz_rep[0], &mut states.lz_rep[0]) == 0 {
                let slot: usize = (prev_item_type & 1) as usize;
                offset = recent_lz_offsets[slot];
                recent_lz_offsets[slot] = recent_lz_offsets[0];
            } else if rd.decode_bit(&mut probs.lz_rep[1], &mut states.lz_rep[1]) == 0 {
                let slot: usize = 1 + (prev_item_type & 1) as usize;
                offset = recent_lz_offsets[slot];
                recent_lz_offsets[slot] = recent_lz_offsets[1];
                recent_lz_offsets[1] = recent_lz_offsets[0];
            } else {
                let slot: usize = 2 + (prev_item_type & 1) as usize;
                offset = recent_lz_offsets[slot];
                recent_lz_offsets[slot] = recent_lz_offsets[2];
                recent_lz_offsets[2] = recent_lz_offsets[1];
                recent_lz_offsets[1] = recent_lz_offsets[0];
            }
            recent_lz_offsets[0] = offset;
            prev_item_type = 1;
            let length: u32 = decode_length(&mut codes, &mut is)?;
            lz_copy(&mut out, pos, offset, length)?;
            pos += length as usize;
        } else {
            let pair: u64;
            if rd.decode_bit(&mut probs.delta, &mut states.delta) == 0 {
                let power: u32 = u32::from(codes.delta_power.decode_symbol(&mut is)?);
                let raw_offset: u32 = decode_delta_offset(&mut codes, &mut is)?;
                pair = (u64::from(power) << 32) | u64::from(raw_offset);
                recent_delta_pairs[3] = recent_delta_pairs[2];
                recent_delta_pairs[2] = recent_delta_pairs[1];
                recent_delta_pairs[1] = recent_delta_pairs[0];
            } else if rd.decode_bit(&mut probs.delta_rep[0], &mut states.delta_rep[0]) == 0 {
                let slot: usize = (prev_item_type >> 1) as usize;
                pair = recent_delta_pairs[slot];
                recent_delta_pairs[slot] = recent_delta_pairs[0];
            } else if rd.decode_bit(&mut probs.delta_rep[1], &mut states.delta_rep[1]) == 0 {
                let slot: usize = 1 + (prev_item_type >> 1) as usize;
                pair = recent_delta_pairs[slot];
                recent_delta_pairs[slot] = recent_delta_pairs[1];
                recent_delta_pairs[1] = recent_delta_pairs[0];
            } else {
                let slot: usize = 2 + (prev_item_type >> 1) as usize;
                pair = recent_delta_pairs[slot];
                recent_delta_pairs[slot] = recent_delta_pairs[2];
                recent_delta_pairs[2] = recent_delta_pairs[1];
                recent_delta_pairs[1] = recent_delta_pairs[0];
            }
            recent_delta_pairs[0] = pair;
            prev_item_type = 2;
            let length: u32 = decode_length(&mut codes, &mut is)?;
            let power: u32 = (pair >> 32) as u32;
            let raw_offset: u32 = pair as u32;
            let span: u32 = 1u32 << power;
            let offset: u32 = raw_offset << power;
            if offset >> power != raw_offset {
                return Err(Error::Decompression(
                    "lzms delta offset overflow".to_owned(),
                ));
            }
            if offset.checked_add(span).is_none() {
                return Err(Error::Decompression("lzms delta span overflow".to_owned()));
            }
            let offset_usize: usize = offset as usize;
            let span_usize: usize = span as usize;
            if offset_usize + span_usize > pos {
                return Err(Error::Decompression(
                    "lzms delta source underruns output".to_owned(),
                ));
            }
            let end: usize = pos
                .checked_add(length as usize)
                .ok_or_else(|| Error::Decompression("lzms delta length overflow".to_owned()))?;
            if end > out_size {
                return Err(Error::Decompression(
                    "lzms delta match overruns output".to_owned(),
                ));
            }
            let mut match_pos: usize = pos - offset_usize;
            let mut dst: usize = pos;
            while dst < end {
                let a: i32 = i32::from(out[match_pos]);
                let b: i32 = i32::from(out[dst - span_usize]);
                let c: i32 = i32::from(out[match_pos - span_usize]);
                out[dst] = (a + b - c) as u8;
                dst += 1;
                match_pos += 1;
            }
            pos = end;
        }
    }

    let mut last_target_usages: Vec<i32> = vec![0i32; 65536];
    x86_filter(&mut out, &mut last_target_usages, true);
    Ok(out)
}

fn x86_filter(data: &mut [u8], last_target_usages: &mut [i32], undo: bool) {
    let size: i32 = data.len() as i32;
    if size <= 17 {
        return;
    }
    for slot in last_target_usages.iter_mut() {
        *slot = -LZMS_X86_ID_WINDOW_SIZE - 1;
    }
    let mut last_x86_pos: i32 = -LZMS_X86_MAX_TRANSLATION_OFFSET - 1;
    let tail: usize = data.len() - 16;
    let mut p: usize = 1;
    while p < tail {
        if !is_potential_opcode(data[p]) {
            p += 1;
            continue;
        }
        p = translate_if_needed(data, p, &mut last_x86_pos, last_target_usages, undo);
    }
}

const fn is_potential_opcode(byte: u8) -> bool {
    matches!(byte, 0x48 | 0x4c | 0xe8 | 0xe9 | 0xf0 | 0xff)
}

fn translate_if_needed(
    data: &mut [u8],
    p: usize,
    last_x86_pos: &mut i32,
    last_target_usages: &mut [i32],
    undo: bool,
) -> usize {
    let mut max_trans_offset: i32 = LZMS_X86_MAX_TRANSLATION_OFFSET;
    let opcode_nbytes: usize;
    let b0: u8 = data[p];
    if b0 >= 0xf0 {
        if b0 & 0x0f != 0 {
            if data.get(p + 1).copied() == Some(0x15) {
                opcode_nbytes = 2;
            } else {
                return p + 1;
            }
        } else if data.get(p + 1).copied() == Some(0x83) && data.get(p + 2).copied() == Some(0x05) {
            opcode_nbytes = 3;
        } else {
            return p + 1;
        }
    } else if b0 <= 0x4c {
        if data.get(p + 2).map(|b: &u8| b & 0x07) == Some(0x05) {
            let b1: u8 = data.get(p + 1).copied().map_or(0, |value: u8| value);
            if b1 == 0x8d
                || (b1 == 0x8b
                    && (b0 & 0x04) == 0
                    && (data.get(p + 2).copied().map_or(0, |value: u8| value) & 0xf0) == 0)
            {
                opcode_nbytes = 3;
            } else {
                return p + 1;
            }
        } else {
            return p + 1;
        }
    } else if b0 & 0x01 != 0 {
        return p + 4;
    } else {
        opcode_nbytes = 1;
        max_trans_offset >>= 1;
    }

    let mut i: i32 = p as i32;
    let opcode_end: usize = p + opcode_nbytes;
    if opcode_end + 4 > data.len() {
        return p + 1;
    }
    let target16: u16;
    if undo {
        if i - *last_x86_pos <= max_trans_offset {
            let n: u32 = read_le32(data, opcode_end);
            write_le32(data, opcode_end, n.wrapping_sub(i as u32));
        }
        target16 = (i as u32).wrapping_add(u32::from(read_le16(data, opcode_end))) as u16;
    } else {
        target16 = (i as u32).wrapping_add(u32::from(read_le16(data, opcode_end))) as u16;
        if i - *last_x86_pos <= max_trans_offset {
            let n: u32 = read_le32(data, opcode_end);
            write_le32(data, opcode_end, n.wrapping_add(i as u32));
        }
    }
    i += opcode_nbytes as i32 + 4 - 1;
    let usage_idx: usize = target16 as usize;
    if i - last_target_usages[usage_idx] <= LZMS_X86_ID_WINDOW_SIZE {
        *last_x86_pos = i;
    }
    last_target_usages[usage_idx] = i;
    opcode_end + 4
}

fn read_le16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn read_le32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

fn write_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Copy)]
enum EncBitClass {
    Main,
    Match,
    Lz,
}

#[derive(Debug)]
struct EncHuffman {
    rebuild_freq: u32,
    num_syms_until_rebuild: u32,
    freqs: Vec<u32>,
    lens: Vec<u8>,
    codewords: Vec<u32>,
}

impl EncHuffman {
    fn new(num_syms: usize, rebuild_freq: u32) -> Self {
        let mut code: Self = Self {
            rebuild_freq,
            num_syms_until_rebuild: rebuild_freq,
            freqs: vec![1u32; num_syms],
            lens: vec![0u8; num_syms],
            codewords: vec![0u32; num_syms],
        };
        code.rebuild();
        code.num_syms_until_rebuild = rebuild_freq;
        code
    }

    fn rebuild(&mut self) {
        make_canonical_lengths(&self.freqs, LZMS_MAX_CODEWORD_LENGTH, &mut self.lens);
        gen_codewords(&self.lens, &mut self.codewords);
        self.num_syms_until_rebuild = self.rebuild_freq;
    }

    fn bump(&mut self, sym: usize) {
        self.freqs[sym] += 1;
        self.num_syms_until_rebuild -= 1;
        if self.num_syms_until_rebuild == 0 {
            self.rebuild();
            for freq in &mut self.freqs {
                *freq = (*freq >> 1) + 1;
            }
        }
    }
}

fn gen_codewords(lens: &[u8], codewords: &mut [u32]) {
    let max_len: usize = LZMS_MAX_CODEWORD_LENGTH as usize;
    let mut len_counts: Vec<u32> = vec![0u32; max_len + 1];
    for &len in lens {
        if len != 0 {
            len_counts[len as usize] += 1;
        }
    }
    let mut next_codewords: Vec<u32> = vec![0u32; max_len + 1];
    for len in 2..=max_len {
        next_codewords[len] = (next_codewords[len - 1] + len_counts[len - 1]) << 1;
    }
    for (sym, &len) in lens.iter().enumerate() {
        if len != 0 {
            codewords[sym] = next_codewords[len as usize];
            next_codewords[len as usize] += 1;
        }
    }
}

struct LzmsEncoder {
    lower_bound: u64,
    range_size: u32,
    cache: u16,
    cache_size: u32,
    rc_out: Vec<u16>,
    rc_emitted: usize,
    os_bitbuf: u64,
    os_bitcount: u32,
    os_units: Vec<u16>,
    main: [ProbabilityEntry; LZMS_NUM_MAIN_PROBS],
    match_probs: [ProbabilityEntry; LZMS_NUM_MATCH_PROBS],
    lz: [ProbabilityEntry; LZMS_NUM_LZ_PROBS],
    main_state: u32,
    match_state: u32,
    lz_state: u32,
    literal: EncHuffman,
    lz_offset: EncHuffman,
    length: EncHuffman,
}

impl LzmsEncoder {
    fn new(num_offset_slots: usize) -> Self {
        let offset_syms: usize = num_offset_slots.max(1);
        Self {
            lower_bound: 0,
            range_size: 0xffff_ffff,
            cache: 0,
            cache_size: 1,
            rc_out: Vec::new(),
            rc_emitted: 0,
            os_bitbuf: 0,
            os_bitcount: 0,
            os_units: Vec::new(),
            main: [ProbabilityEntry::init(); LZMS_NUM_MAIN_PROBS],
            match_probs: [ProbabilityEntry::init(); LZMS_NUM_MATCH_PROBS],
            lz: [ProbabilityEntry::init(); LZMS_NUM_LZ_PROBS],
            main_state: 0,
            match_state: 0,
            lz_state: 0,
            literal: EncHuffman::new(LZMS_NUM_LITERAL_SYMS, LZMS_LITERAL_CODE_REBUILD_FREQ),
            lz_offset: EncHuffman::new(offset_syms, LZMS_LZ_OFFSET_CODE_REBUILD_FREQ),
            length: EncHuffman::new(LZMS_NUM_LENGTH_SYMS, LZMS_LENGTH_CODE_REBUILD_FREQ),
        }
    }

    fn shift_low(&mut self) {
        if (self.lower_bound as u32) < 0xffff_0000 || (self.lower_bound >> 32) != 0 {
            loop {
                let carry: u16 = (self.lower_bound >> 32) as u16;
                if self.rc_emitted == 0 {
                    self.rc_emitted = 1;
                } else {
                    self.rc_out.push(self.cache.wrapping_add(carry));
                }
                self.cache = 0xffff;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.lower_bound >> 16) & 0xffff) as u16;
        }
        self.cache_size += 1;
        self.lower_bound = (self.lower_bound & 0xffff) << 16;
    }

    fn encode_bit(&mut self, class: EncBitClass, bit: u32) {
        let (states, state_p, num_states): (&mut [ProbabilityEntry], &mut u32, u32) = match class {
            EncBitClass::Main => (
                &mut self.main,
                &mut self.main_state,
                LZMS_NUM_MAIN_PROBS as u32,
            ),
            EncBitClass::Match => (
                &mut self.match_probs,
                &mut self.match_state,
                LZMS_NUM_MATCH_PROBS as u32,
            ),
            EncBitClass::Lz => (&mut self.lz, &mut self.lz_state, LZMS_NUM_LZ_PROBS as u32),
        };
        let index: usize = *state_p as usize;
        *state_p = ((*state_p << 1) | bit) & (num_states - 1);
        let prob: u32 = states[index].probability();
        states[index].update(bit);
        if self.range_size <= 0xffff {
            self.range_size <<= 16;
            self.shift_low();
        }
        let bound: u32 = (self.range_size >> LZMS_PROBABILITY_BITS) * prob;
        if bit == 0 {
            self.range_size = bound;
        } else {
            self.lower_bound += u64::from(bound);
            self.range_size -= bound;
        }
    }

    fn write_bits(&mut self, bits: u32, num_bits: u32) {
        if num_bits == 0 {
            return;
        }
        self.os_bitcount += num_bits;
        self.os_bitbuf = (self.os_bitbuf << num_bits) | u64::from(bits);
        while self.os_bitcount >= 16 {
            self.os_bitcount -= 16;
            let unit: u16 = (self.os_bitbuf >> self.os_bitcount) as u16;
            self.os_units.push(unit);
        }
    }

    fn encode_literal(&mut self, byte: u8) {
        self.encode_bit(EncBitClass::Main, 0);
        let sym: usize = byte as usize;
        let code: u32 = self.literal.codewords[sym];
        let len: u32 = u32::from(self.literal.lens[sym]);
        self.write_bits(code, len);
        self.literal.bump(sym);
    }

    fn encode_lz_explicit(&mut self, offset: u32, length: u32) {
        self.encode_bit(EncBitClass::Main, 1);
        self.encode_bit(EncBitClass::Match, 0);
        self.encode_bit(EncBitClass::Lz, 0);
        let off_slot: usize = get_offset_slot(offset);
        let off_code: u32 = self.lz_offset.codewords[off_slot];
        let off_len: u32 = u32::from(self.lz_offset.lens[off_slot]);
        self.write_bits(off_code, off_len);
        self.lz_offset.bump(off_slot);
        self.write_bits(
            offset - LZMS_OFFSET_SLOT_BASE[off_slot],
            u32::from(LZMS_EXTRA_OFFSET_BITS[off_slot]),
        );
        let len_slot: usize = get_slot(length, &LZMS_LENGTH_SLOT_BASE, LZMS_NUM_LENGTH_SYMS);
        let len_code: u32 = self.length.codewords[len_slot];
        let len_len: u32 = u32::from(self.length.lens[len_slot]);
        self.write_bits(len_code, len_len);
        self.length.bump(len_slot);
        self.write_bits(
            length - LZMS_LENGTH_SLOT_BASE[len_slot],
            u32::from(LZMS_EXTRA_LENGTH_BITS[len_slot]),
        );
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..4 {
            self.shift_low();
        }
        if self.os_bitcount != 0 {
            let unit: u16 = (self.os_bitbuf << (16 - self.os_bitcount)) as u16;
            self.os_units.push(unit);
        }
        let total_units: usize = (self.rc_out.len() + self.os_units.len()).max(2);
        let mut units: Vec<u16> = vec![0u16; total_units];
        for (i, unit) in self.rc_out.iter().enumerate() {
            units[i] = *unit;
        }
        for (i, unit) in self.os_units.iter().enumerate() {
            units[total_units - 1 - i] = *unit;
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(total_units * 2);
        for unit in units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }
}

const LZMS_ENC_MIN_MATCH: u32 = 3;
const LZMS_ENC_MAX_MATCH: u32 = 1 << 12;
const LZMS_ENC_HASH_BITS: u32 = 15;
const LZMS_ENC_HASH_SIZE: usize = 1 << LZMS_ENC_HASH_BITS;
const LZMS_ENC_MAX_CHAIN: u32 = 32;

fn enc_hash3(data: &[u8], pos: usize) -> usize {
    let a: u32 = u32::from(data[pos]);
    let b: u32 = u32::from(data[pos + 1]);
    let c: u32 = u32::from(data[pos + 2]);
    let h: u32 = (a << 16) ^ (b << 8) ^ c;
    ((h.wrapping_mul(2_654_435_761)) >> (32 - LZMS_ENC_HASH_BITS)) as usize
}

fn enc_find_match(data: &[u8], pos: usize, head: &[i32], prev: &[i32]) -> Option<(u32, u32)> {
    let limit: usize = data.len();
    if pos + LZMS_ENC_MIN_MATCH as usize > limit {
        return None;
    }
    let max_len: usize = (limit - pos).min(LZMS_ENC_MAX_MATCH as usize);
    let mut best_len: usize = 0;
    let mut best_off: usize = 0;
    let mut cand: i32 = head[enc_hash3(data, pos)];
    let mut chain: u32 = 0;
    while cand >= 0 && chain < LZMS_ENC_MAX_CHAIN {
        let cand_pos: usize = cand as usize;
        let offset: usize = pos - cand_pos;
        if offset == 0 || offset > pos {
            break;
        }
        let mut len: usize = 0;
        while len < max_len && data[cand_pos + len] == data[pos + len] {
            len += 1;
        }
        if len > best_len {
            best_len = len;
            best_off = offset;
            if len >= max_len {
                break;
            }
        }
        cand = prev[cand_pos];
        chain += 1;
    }
    if best_len >= LZMS_ENC_MIN_MATCH as usize {
        Some((best_off as u32, best_len as u32))
    } else {
        None
    }
}

/// Compress a raw byte buffer into a single LZMS chunk decodable by
/// [`lzms_decompress`].
///
/// This is the inverse of the in-tree decoder: a greedy LZ77 parse over a
/// hash-chain match finder, the same forward binary range coder and backward
/// adaptive-Huffman bitstream the decoder reads, and the encode-direction x86
/// call/jump pre-filter. It emits only literals and explicit LZ matches (no
/// repeat or delta items), which keeps the output a valid LZMS stream while
/// avoiding the recent-offset state machine. It is used to author
/// spec-conformant LZMS payloads (for example LZMS-compressed cabinets) and to
/// validate the decoder by round-trip.
pub fn lzms_compress(input: &[u8]) -> Vec<u8> {
    let out_size: usize = input.len();
    if out_size == 0 {
        return vec![0u8; 4];
    }

    let mut filtered: Vec<u8> = input.to_vec();
    let mut enc_usages: Vec<i32> = vec![0i32; 65536];
    x86_filter(&mut filtered, &mut enc_usages, false);

    let mut enc: LzmsEncoder = LzmsEncoder::new(get_num_offset_slots(out_size));
    let mut head: Vec<i32> = vec![-1i32; LZMS_ENC_HASH_SIZE];
    let mut prev: Vec<i32> = vec![-1i32; out_size];

    let mut pos: usize = 0;
    while pos < out_size {
        let found: Option<(u32, u32)> = if pos + LZMS_ENC_MIN_MATCH as usize <= out_size {
            enc_find_match(&filtered, pos, &head, &prev)
        } else {
            None
        };
        let advance: usize = if let Some((offset, length)) = found {
            enc.encode_lz_explicit(offset, length);
            length as usize
        } else {
            enc.encode_literal(filtered[pos]);
            1
        };
        let insert_end: usize = (pos + advance).min(out_size.saturating_sub(2));
        let mut ins: usize = pos;
        while ins < insert_end {
            let h: usize = enc_hash3(&filtered, ins);
            prev[ins] = head[h];
            head[h] = ins as i32;
            ins += 1;
        }
        pos += advance;
    }

    enc.finish()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum BitClass {
        Main,
        Match,
        Lz,
    }

    enum Item {
        Literal(u8),
        LzExplicit { offset: u32, length: u32 },
    }

    struct EncHuff {
        rebuild_freq: u32,
        num_syms_until_rebuild: u32,
        freqs: Vec<u32>,
        lens: Vec<u8>,
        codewords: Vec<u32>,
    }

    impl EncHuff {
        fn new(num_syms: usize, rebuild_freq: u32) -> Self {
            let mut h: Self = Self {
                rebuild_freq,
                num_syms_until_rebuild: rebuild_freq,
                freqs: vec![1u32; num_syms],
                lens: vec![0u8; num_syms],
                codewords: vec![0u32; num_syms],
            };
            h.rebuild();
            h.num_syms_until_rebuild = rebuild_freq;
            h
        }

        fn rebuild(&mut self) {
            make_canonical_lengths(&self.freqs, LZMS_MAX_CODEWORD_LENGTH, &mut self.lens);
            gen_codewords(&self.lens, &mut self.codewords);
            self.num_syms_until_rebuild = self.rebuild_freq;
        }
    }

    fn gen_codewords(lens: &[u8], codewords: &mut [u32]) {
        let max_len: usize = LZMS_MAX_CODEWORD_LENGTH as usize;
        let mut len_counts: Vec<u32> = vec![0u32; max_len + 1];
        for &len in lens {
            if len != 0 {
                len_counts[len as usize] += 1;
            }
        }
        let mut next_codewords: Vec<u32> = vec![0u32; max_len + 1];
        for len in 2..=max_len {
            next_codewords[len] = (next_codewords[len - 1] + len_counts[len - 1]) << 1;
        }
        for (sym, &len) in lens.iter().enumerate() {
            if len != 0 {
                codewords[sym] = next_codewords[len as usize];
                next_codewords[len as usize] += 1;
            }
        }
    }

    struct RefEncoder {
        lower_bound: u64,
        range_size: u32,
        cache: u16,
        cache_size: u32,
        rc_out: Vec<u16>,
        rc_emitted: usize,
        os_bitbuf: u64,
        os_bitcount: u32,
        os_units: Vec<u16>,
        main: [ProbabilityEntry; LZMS_NUM_MAIN_PROBS],
        match_probs: [ProbabilityEntry; LZMS_NUM_MATCH_PROBS],
        lz: [ProbabilityEntry; LZMS_NUM_LZ_PROBS],
        main_state: u32,
        match_state: u32,
        lz_state: u32,
        literal: EncHuff,
        lz_offset: EncHuff,
        length: EncHuff,
    }

    impl RefEncoder {
        fn new(num_offset_slots: usize) -> Self {
            let offset_syms: usize = num_offset_slots.max(1);
            Self {
                lower_bound: 0,
                range_size: 0xffff_ffff,
                cache: 0,
                cache_size: 1,
                rc_out: Vec::new(),
                rc_emitted: 0,
                os_bitbuf: 0,
                os_bitcount: 0,
                os_units: Vec::new(),
                main: [ProbabilityEntry::init(); LZMS_NUM_MAIN_PROBS],
                match_probs: [ProbabilityEntry::init(); LZMS_NUM_MATCH_PROBS],
                lz: [ProbabilityEntry::init(); LZMS_NUM_LZ_PROBS],
                main_state: 0,
                match_state: 0,
                lz_state: 0,
                literal: EncHuff::new(LZMS_NUM_LITERAL_SYMS, LZMS_LITERAL_CODE_REBUILD_FREQ),
                lz_offset: EncHuff::new(offset_syms, LZMS_LZ_OFFSET_CODE_REBUILD_FREQ),
                length: EncHuff::new(LZMS_NUM_LENGTH_SYMS, LZMS_LENGTH_CODE_REBUILD_FREQ),
            }
        }

        fn shift_low(&mut self) {
            if (self.lower_bound as u32) < 0xffff_0000 || (self.lower_bound >> 32) != 0 {
                loop {
                    let carry: u16 = (self.lower_bound >> 32) as u16;
                    if self.rc_emitted == 0 {
                        self.rc_emitted = 1;
                    } else {
                        self.rc_out.push(self.cache.wrapping_add(carry));
                    }
                    self.cache = 0xffff;
                    self.cache_size -= 1;
                    if self.cache_size == 0 {
                        break;
                    }
                }
                self.cache = ((self.lower_bound >> 16) & 0xffff) as u16;
            }
            self.cache_size += 1;
            self.lower_bound = (self.lower_bound & 0xffff) << 16;
        }

        fn encode_bit(&mut self, class: BitClass, bit: u32) {
            let (states, state_p, num_states): (&mut [ProbabilityEntry], &mut u32, u32) =
                match class {
                    BitClass::Main => (
                        &mut self.main,
                        &mut self.main_state,
                        LZMS_NUM_MAIN_PROBS as u32,
                    ),
                    BitClass::Match => (
                        &mut self.match_probs,
                        &mut self.match_state,
                        LZMS_NUM_MATCH_PROBS as u32,
                    ),
                    BitClass::Lz => (&mut self.lz, &mut self.lz_state, LZMS_NUM_LZ_PROBS as u32),
                };
            let index: usize = *state_p as usize;
            *state_p = ((*state_p << 1) | bit) & (num_states - 1);
            let prob: u32 = states[index].probability();
            states[index].update(bit);
            if self.range_size <= 0xffff {
                self.range_size <<= 16;
                self.shift_low();
            }
            let bound: u32 = (self.range_size >> LZMS_PROBABILITY_BITS) * prob;
            if bit == 0 {
                self.range_size = bound;
            } else {
                self.lower_bound += u64::from(bound);
                self.range_size -= bound;
            }
        }

        fn write_bits(&mut self, bits: u32, num_bits: u32) {
            if num_bits == 0 {
                return;
            }
            self.os_bitcount += num_bits;
            self.os_bitbuf = (self.os_bitbuf << num_bits) | u64::from(bits);
            while self.os_bitcount >= 16 {
                self.os_bitcount -= 16;
                let unit: u16 = (self.os_bitbuf >> self.os_bitcount) as u16;
                self.os_units.push(unit);
            }
        }

        fn encode_literal(&mut self, byte: u8) {
            self.encode_bit(BitClass::Main, 0);
            let sym: usize = byte as usize;
            let code: u32 = self.literal.codewords[sym];
            let len: u32 = u32::from(self.literal.lens[sym]);
            self.write_bits(code, len);
            Self::bump(&mut self.literal, sym);
        }

        fn encode_lz_explicit(&mut self, offset: u32, length: u32) {
            self.encode_bit(BitClass::Main, 1);
            self.encode_bit(BitClass::Match, 0);
            self.encode_bit(BitClass::Lz, 0);
            let off_slot: usize = get_offset_slot(offset);
            let off_code: u32 = self.lz_offset.codewords[off_slot];
            let off_len: u32 = u32::from(self.lz_offset.lens[off_slot]);
            self.write_bits(off_code, off_len);
            Self::bump(&mut self.lz_offset, off_slot);
            self.write_bits(
                offset - LZMS_OFFSET_SLOT_BASE[off_slot],
                u32::from(LZMS_EXTRA_OFFSET_BITS[off_slot]),
            );
            let len_slot: usize = length_slot(length);
            let len_code: u32 = self.length.codewords[len_slot];
            let len_len: u32 = u32::from(self.length.lens[len_slot]);
            self.write_bits(len_code, len_len);
            Self::bump(&mut self.length, len_slot);
            self.write_bits(
                length - LZMS_LENGTH_SLOT_BASE[len_slot],
                u32::from(LZMS_EXTRA_LENGTH_BITS[len_slot]),
            );
        }

        fn bump(h: &mut EncHuff, sym: usize) {
            h.freqs[sym] += 1;
            h.num_syms_until_rebuild -= 1;
            if h.num_syms_until_rebuild == 0 {
                h.rebuild();
                for f in &mut h.freqs {
                    *f = (*f >> 1) + 1;
                }
            }
        }

        fn finish(mut self, out_size: usize) -> Vec<u8> {
            for _ in 0..4 {
                self.shift_low();
            }
            if self.os_bitcount != 0 {
                let unit: u16 = (self.os_bitbuf << (16 - self.os_bitcount)) as u16;
                self.os_units.push(unit);
            }
            let total_units: usize = out_size
                .div_ceil(2)
                .max(self.rc_out.len() + self.os_units.len());
            let mut units: Vec<u16> = vec![0u16; total_units];
            for (i, unit) in self.rc_out.iter().enumerate() {
                units[i] = *unit;
            }
            for (i, unit) in self.os_units.iter().enumerate() {
                units[total_units - 1 - i] = *unit;
            }
            let mut bytes: Vec<u8> = Vec::with_capacity(total_units * 2);
            for unit in units {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes
        }
    }

    fn length_slot(length: u32) -> usize {
        get_slot(length, &LZMS_LENGTH_SLOT_BASE, LZMS_NUM_LENGTH_SYMS)
    }

    fn encode_items(items: &[Item], out_size: usize) -> Vec<u8> {
        let mut enc: RefEncoder = RefEncoder::new(get_num_offset_slots(out_size));
        for item in items {
            match *item {
                Item::Literal(byte) => enc.encode_literal(byte),
                Item::LzExplicit { offset, length } => enc.encode_lz_explicit(offset, length),
            }
        }
        enc.finish(out_size)
    }

    fn encode_literals_only(data: &[u8]) -> Vec<u8> {
        let items: Vec<Item> = data.iter().map(|&b: &u8| Item::Literal(b)).collect();
        encode_items(&items, data.len())
    }

    #[test]
    fn make_canonical_lengths_kraft_sum_holds() {
        let freqs: Vec<u32> = vec![10, 1, 1, 1, 5, 3, 2, 2];
        let mut lens: Vec<u8> = vec![0u8; freqs.len()];
        make_canonical_lengths(&freqs, LZMS_MAX_CODEWORD_LENGTH, &mut lens);
        let mut sum: f64 = 0.0;
        for &len in &lens {
            assert!(len >= 1 && u32::from(len) <= LZMS_MAX_CODEWORD_LENGTH);
            sum += 2f64.powi(-i32::from(len));
        }
        assert!((sum - 1.0).abs() < 1e-9, "kraft sum {sum}");
    }

    #[test]
    fn offset_slot_tables_are_monotonic_and_consistent() {
        for i in 0..LZMS_MAX_NUM_OFFSET_SYMS {
            assert!(
                LZMS_OFFSET_SLOT_BASE[i] < LZMS_OFFSET_SLOT_BASE[i + 1],
                "offset slot base not strictly increasing at {i}"
            );
        }
        assert_eq!(LZMS_OFFSET_SLOT_BASE[0], 1);
        assert_eq!(LZMS_OFFSET_SLOT_BASE[8], 0x9);
        assert_eq!(LZMS_OFFSET_SLOT_BASE[LZMS_MAX_NUM_OFFSET_SYMS], 0x465b_e4a5);
    }

    #[test]
    fn length_slot_tables_match_reference() {
        assert_eq!(LZMS_LENGTH_SLOT_BASE[0], 1);
        assert_eq!(LZMS_LENGTH_SLOT_BASE[LZMS_NUM_LENGTH_SYMS], 0x4001_08ab);
        for i in 0..LZMS_NUM_LENGTH_SYMS {
            assert!(LZMS_LENGTH_SLOT_BASE[i] < LZMS_LENGTH_SLOT_BASE[i + 1]);
        }
    }

    #[test]
    fn round_trips_literals_only_short() {
        let data: &[u8] = b"abcdefghijklmnop";
        let encoded: Vec<u8> = encode_literals_only(data);
        let decoded: Vec<u8> = lzms_decompress(&encoded, data.len()).expect("decode lzms literals");
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_literals_only_repeated_alphabet() {
        let mut data: Vec<u8> = Vec::new();
        for _ in 0..50 {
            data.extend_from_slice(b"the quick brown fox 0123456789 ");
        }
        let encoded: Vec<u8> = encode_literals_only(&data);
        let decoded: Vec<u8> = lzms_decompress(&encoded, data.len()).expect("decode lzms");
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_literals_spanning_huffman_rebuild() {
        let mut data: Vec<u8> = Vec::with_capacity(3000);
        let mut state: u32 = 0x1234_5678;
        for _ in 0..3000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            data.push((state >> 16) as u8);
        }
        let encoded: Vec<u8> = encode_literals_only(&data);
        let decoded: Vec<u8> = lzms_decompress(&encoded, data.len()).expect("decode lzms rebuild");
        assert_eq!(decoded, data);
    }

    #[test]
    fn round_trips_explicit_lz_match() {
        let mut items: Vec<Item> = Vec::new();
        for &b in b"abcdefgh" {
            items.push(Item::Literal(b));
        }
        items.push(Item::LzExplicit {
            offset: 8,
            length: 8,
        });
        for &b in b"XYZ" {
            items.push(Item::Literal(b));
        }
        let out_size: usize = 8 + 8 + 3;
        let encoded: Vec<u8> = encode_items(&items, out_size);
        let decoded: Vec<u8> = lzms_decompress(&encoded, out_size).expect("decode lz match");
        assert_eq!(decoded, b"abcdefghabcdefghXYZ");
    }

    #[test]
    fn round_trips_overlapping_lz_run() {
        let items: Vec<Item> = vec![
            Item::Literal(b'A'),
            Item::LzExplicit {
                offset: 1,
                length: 9,
            },
        ];
        let out_size: usize = 10;
        let encoded: Vec<u8> = encode_items(&items, out_size);
        let decoded: Vec<u8> = lzms_decompress(&encoded, out_size).expect("decode overlap run");
        assert_eq!(decoded, b"AAAAAAAAAA");
    }

    #[test]
    fn round_trips_mixed_literals_and_matches() {
        let unit: &[u8] = b"abcdefghij";
        let mut data: Vec<u8> = Vec::new();
        for _ in 0..30 {
            data.extend_from_slice(unit);
        }
        let mut items: Vec<Item> = Vec::new();
        for &b in unit {
            items.push(Item::Literal(b));
        }
        let mut produced: usize = unit.len();
        while produced + unit.len() <= data.len() {
            items.push(Item::LzExplicit {
                offset: unit.len() as u32,
                length: unit.len() as u32,
            });
            produced += unit.len();
        }
        while produced < data.len() {
            items.push(Item::Literal(data[produced]));
            produced += 1;
        }
        let encoded: Vec<u8> = encode_items(&items, data.len());
        let decoded: Vec<u8> = lzms_decompress(&encoded, data.len()).expect("decode mixed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn rejects_odd_length_input() {
        let input: [u8; 5] = [0u8; 5];
        assert!(lzms_decompress(&input, 4).is_err());
    }

    #[test]
    fn zero_output_size_is_empty() {
        let input: [u8; 4] = [0u8; 4];
        let out: Vec<u8> = lzms_decompress(&input, 0).expect("empty");
        assert!(out.is_empty());
    }

    fn enc_dec_round_trip(data: &[u8]) {
        let encoded: Vec<u8> = lzms_compress(data);
        assert_eq!(
            encoded.len() % 2,
            0,
            "encoder must emit 16-bit-aligned output"
        );
        let decoded: Vec<u8> =
            lzms_decompress(&encoded, data.len()).expect("decode self-encoded lzms");
        assert_eq!(
            decoded, data,
            "in-tree lzms encoder/decoder not byte-identical"
        );
    }

    #[test]
    fn encoder_round_trips_text_with_matches() {
        let mut data: Vec<u8> = Vec::new();
        for _ in 0..200 {
            data.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        let encoded: Vec<u8> = lzms_compress(&data);
        assert!(
            encoded.len() < data.len(),
            "encoder must compress highly repetitive text ({} >= {})",
            encoded.len(),
            data.len()
        );
        enc_dec_round_trip(&data);
    }

    #[test]
    fn encoder_round_trips_pseudo_random_bytes() {
        let mut data: Vec<u8> = Vec::with_capacity(20_000);
        let mut state: u32 = 0x9e37_79b9;
        for _ in 0..20_000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            data.push((state >> 15) as u8);
        }
        enc_dec_round_trip(&data);
    }

    #[test]
    fn encoder_round_trips_x86_trigger_heavy_bytes() {
        let triggers: [u8; 6] = [0x48, 0x4c, 0xe8, 0xe9, 0xf0, 0xff];
        let mut data: Vec<u8> = Vec::with_capacity(16_384);
        let mut state: u32 = 0x1357_2468;
        while data.len() < 16_384 {
            state = state.wrapping_mul(214_013).wrapping_add(2_531_011);
            data.push(triggers[(state >> 24) as usize % triggers.len()]);
            data.push((state >> 8) as u8);
            data.push((state >> 16) as u8);
            data.push(0x05);
            data.push((state >> 3) as u8);
        }
        enc_dec_round_trip(&data);
    }

    #[test]
    fn encoder_round_trips_short_and_edge_lengths() {
        for n in [1usize, 2, 3, 4, 5, 7, 16, 17, 18, 31, 64] {
            let data: Vec<u8> = (0..n).map(|i: usize| (i.wrapping_mul(37)) as u8).collect();
            enc_dec_round_trip(&data);
        }
    }
}
