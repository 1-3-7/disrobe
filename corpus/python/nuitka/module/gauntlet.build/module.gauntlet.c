/* Generated code for Python module 'gauntlet'
 * created by Nuitka version 4.1.1
 *
 * This code is in part copyright 2026 Kay Hayen.
 *
 * Licensed under the GNU Affero General Public License, Version 3 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License in "LICENSE.txt" and the runtime
 * exception granted in "LICENSE-RUNTIME.txt" from Nuitka source code. For
 * deploying the generated code it is intended to not restrict distributing
 * created binaries.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "nuitka/prelude.h"

#include "nuitka/unfreezing.h"

#include "__helpers.h"



/* The "module_gauntlet" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_gauntlet;
PyDictObject *moduledict_gauntlet;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9;
PyObject *const_str_plain_a;
PyObject *const_str_plain_total;
PyObject *const_str_plain_factor;
PyObject *const_str_plain_greet;
PyObject *const_str_plain_BANNER;
PyObject *const_str_plain_fib;
PyObject *const_tuple_int_pos_20_tuple;
PyObject *const_str_plain_accumulate;
PyObject *const_int_pos_3;
PyObject *const_int_pos_5;
PyObject *const_int_pos_7;
PyObject *const_str_plain_SEED;
PyObject *const_str_plain_squares;
PyObject *const_tuple_int_pos_4_tuple;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_str_plain_annotations;
PyObject *const_str_digest_17758251adb19c3d0df3013b5efd0f18;
PyObject *const_str_plain_str;
PyObject *const_int_pos_1337;
PyObject *const_str_plain_int;
PyObject *const_dict_e64cc0c4534221dfd66afecde3b815f7;
PyObject *const_dict_6b4ef39d483624f4dfea54e4093b9d1a;
PyObject *const_tuple_int_pos_2_tuple;
PyObject *const_dict_714c8f4d2e45bcee12b901fe97bd646f;
PyObject *const_dict_fa591dc696b12f65b12bb151a1a36846;
PyObject *const_dict_85b825f4db9c19f334e726fd877a8261;
PyObject *const_str_plain_main;
PyObject *const_str_digest_07d0285b5381b31ce6c790ea1eb799a5;
PyObject *const_str_digest_d69802e95c91f8ac63217eb66261fba3;
PyObject *const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple;
PyObject *const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple;
PyObject *const_tuple_str_plain_name_tuple;
PyObject *const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple;
PyObject *const_tuple_str_plain_n_tuple;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[36];
#endif

static PyObject *module_filename_obj = NULL;

/* Indicator if this modules private constants were created yet. */
static bool constants_created = false;

/* Function to create module private constants. */
static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("gauntlet"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 36) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 36 values, got %d\n",
                    UN_TRANSLATE("gauntlet"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9", mod_consts.const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_a", mod_consts.const_str_plain_a);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_plain_a);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_total", mod_consts.const_str_plain_total);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_str_plain_total);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_factor", mod_consts.const_str_plain_factor);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_plain_factor);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_greet", mod_consts.const_str_plain_greet);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_str_plain_greet);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_BANNER", mod_consts.const_str_plain_BANNER);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_str_plain_BANNER);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_fib", mod_consts.const_str_plain_fib);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_plain_fib);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_20_tuple", mod_consts.const_tuple_int_pos_20_tuple);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_20_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_accumulate", mod_consts.const_str_plain_accumulate);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_str_plain_accumulate);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_3", mod_consts.const_int_pos_3);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_int_pos_3);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_5", mod_consts.const_int_pos_5);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_int_pos_5);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_7", mod_consts.const_int_pos_7);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_int_pos_7);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_SEED", mod_consts.const_str_plain_SEED);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_str_plain_SEED);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_squares", mod_consts.const_str_plain_squares);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_str_plain_squares);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_4_tuple", mod_consts.const_tuple_int_pos_4_tuple);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_4_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[16] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_annotations", mod_consts.const_str_plain_annotations);
mod_consts_hash[17] = DEEP_HASH(tstate, mod_consts.const_str_plain_annotations);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_17758251adb19c3d0df3013b5efd0f18", mod_consts.const_str_digest_17758251adb19c3d0df3013b5efd0f18);
mod_consts_hash[18] = DEEP_HASH(tstate, mod_consts.const_str_digest_17758251adb19c3d0df3013b5efd0f18);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_str", mod_consts.const_str_plain_str);
mod_consts_hash[19] = DEEP_HASH(tstate, mod_consts.const_str_plain_str);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_1337", mod_consts.const_int_pos_1337);
mod_consts_hash[20] = DEEP_HASH(tstate, mod_consts.const_int_pos_1337);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_int", mod_consts.const_str_plain_int);
mod_consts_hash[21] = DEEP_HASH(tstate, mod_consts.const_str_plain_int);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_e64cc0c4534221dfd66afecde3b815f7", mod_consts.const_dict_e64cc0c4534221dfd66afecde3b815f7);
mod_consts_hash[22] = DEEP_HASH(tstate, mod_consts.const_dict_e64cc0c4534221dfd66afecde3b815f7);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_6b4ef39d483624f4dfea54e4093b9d1a", mod_consts.const_dict_6b4ef39d483624f4dfea54e4093b9d1a);
mod_consts_hash[23] = DEEP_HASH(tstate, mod_consts.const_dict_6b4ef39d483624f4dfea54e4093b9d1a);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_2_tuple", mod_consts.const_tuple_int_pos_2_tuple);
mod_consts_hash[24] = DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_2_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_714c8f4d2e45bcee12b901fe97bd646f", mod_consts.const_dict_714c8f4d2e45bcee12b901fe97bd646f);
mod_consts_hash[25] = DEEP_HASH(tstate, mod_consts.const_dict_714c8f4d2e45bcee12b901fe97bd646f);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_fa591dc696b12f65b12bb151a1a36846", mod_consts.const_dict_fa591dc696b12f65b12bb151a1a36846);
mod_consts_hash[26] = DEEP_HASH(tstate, mod_consts.const_dict_fa591dc696b12f65b12bb151a1a36846);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_85b825f4db9c19f334e726fd877a8261", mod_consts.const_dict_85b825f4db9c19f334e726fd877a8261);
mod_consts_hash[27] = DEEP_HASH(tstate, mod_consts.const_dict_85b825f4db9c19f334e726fd877a8261);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_main", mod_consts.const_str_plain_main);
mod_consts_hash[28] = DEEP_HASH(tstate, mod_consts.const_str_plain_main);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_07d0285b5381b31ce6c790ea1eb799a5", mod_consts.const_str_digest_07d0285b5381b31ce6c790ea1eb799a5);
mod_consts_hash[29] = DEEP_HASH(tstate, mod_consts.const_str_digest_07d0285b5381b31ce6c790ea1eb799a5);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3", mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3);
mod_consts_hash[30] = DEEP_HASH(tstate, mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple", mod_consts.const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple);
mod_consts_hash[31] = DEEP_HASH(tstate, mod_consts.const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple", mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
mod_consts_hash[32] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_name_tuple", mod_consts.const_tuple_str_plain_name_tuple);
mod_consts_hash[33] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_name_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple", mod_consts.const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple);
mod_consts_hash[34] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
mod_consts_hash[35] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple);
#endif
    }
}

// We want to be able to initialize the "__main__" constants in any case.
#if 0
void createMainModuleConstants(PyThreadState *tstate) {
    createModuleConstants(tstate);
}
#endif

/* Function to verify module private constants for non-corruption. */
#ifndef __NUITKA_NO_ASSERT__
void checkModuleConstants_gauntlet(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9", mod_consts.const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9) && "mod_consts.const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_a", mod_consts.const_str_plain_a);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_plain_a) && "mod_consts.const_str_plain_a");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_total", mod_consts.const_str_plain_total);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_str_plain_total) && "mod_consts.const_str_plain_total");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_factor", mod_consts.const_str_plain_factor);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_plain_factor) && "mod_consts.const_str_plain_factor");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_greet", mod_consts.const_str_plain_greet);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_str_plain_greet) && "mod_consts.const_str_plain_greet");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_BANNER", mod_consts.const_str_plain_BANNER);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_str_plain_BANNER) && "mod_consts.const_str_plain_BANNER");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_fib", mod_consts.const_str_plain_fib);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_plain_fib) && "mod_consts.const_str_plain_fib");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_20_tuple", mod_consts.const_tuple_int_pos_20_tuple);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_20_tuple) && "mod_consts.const_tuple_int_pos_20_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_accumulate", mod_consts.const_str_plain_accumulate);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_str_plain_accumulate) && "mod_consts.const_str_plain_accumulate");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_3", mod_consts.const_int_pos_3);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_int_pos_3) && "mod_consts.const_int_pos_3");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_5", mod_consts.const_int_pos_5);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_int_pos_5) && "mod_consts.const_int_pos_5");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_7", mod_consts.const_int_pos_7);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_int_pos_7) && "mod_consts.const_int_pos_7");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_SEED", mod_consts.const_str_plain_SEED);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_str_plain_SEED) && "mod_consts.const_str_plain_SEED");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_squares", mod_consts.const_str_plain_squares);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_str_plain_squares) && "mod_consts.const_str_plain_squares");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_4_tuple", mod_consts.const_tuple_int_pos_4_tuple);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_4_tuple) && "mod_consts.const_tuple_int_pos_4_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[16] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_annotations", mod_consts.const_str_plain_annotations);
assert(mod_consts_hash[17] == DEEP_HASH(tstate, mod_consts.const_str_plain_annotations) && "mod_consts.const_str_plain_annotations");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_17758251adb19c3d0df3013b5efd0f18", mod_consts.const_str_digest_17758251adb19c3d0df3013b5efd0f18);
assert(mod_consts_hash[18] == DEEP_HASH(tstate, mod_consts.const_str_digest_17758251adb19c3d0df3013b5efd0f18) && "mod_consts.const_str_digest_17758251adb19c3d0df3013b5efd0f18");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_str", mod_consts.const_str_plain_str);
assert(mod_consts_hash[19] == DEEP_HASH(tstate, mod_consts.const_str_plain_str) && "mod_consts.const_str_plain_str");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_1337", mod_consts.const_int_pos_1337);
assert(mod_consts_hash[20] == DEEP_HASH(tstate, mod_consts.const_int_pos_1337) && "mod_consts.const_int_pos_1337");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_int", mod_consts.const_str_plain_int);
assert(mod_consts_hash[21] == DEEP_HASH(tstate, mod_consts.const_str_plain_int) && "mod_consts.const_str_plain_int");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_e64cc0c4534221dfd66afecde3b815f7", mod_consts.const_dict_e64cc0c4534221dfd66afecde3b815f7);
assert(mod_consts_hash[22] == DEEP_HASH(tstate, mod_consts.const_dict_e64cc0c4534221dfd66afecde3b815f7) && "mod_consts.const_dict_e64cc0c4534221dfd66afecde3b815f7");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_6b4ef39d483624f4dfea54e4093b9d1a", mod_consts.const_dict_6b4ef39d483624f4dfea54e4093b9d1a);
assert(mod_consts_hash[23] == DEEP_HASH(tstate, mod_consts.const_dict_6b4ef39d483624f4dfea54e4093b9d1a) && "mod_consts.const_dict_6b4ef39d483624f4dfea54e4093b9d1a");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_2_tuple", mod_consts.const_tuple_int_pos_2_tuple);
assert(mod_consts_hash[24] == DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_2_tuple) && "mod_consts.const_tuple_int_pos_2_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_714c8f4d2e45bcee12b901fe97bd646f", mod_consts.const_dict_714c8f4d2e45bcee12b901fe97bd646f);
assert(mod_consts_hash[25] == DEEP_HASH(tstate, mod_consts.const_dict_714c8f4d2e45bcee12b901fe97bd646f) && "mod_consts.const_dict_714c8f4d2e45bcee12b901fe97bd646f");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_fa591dc696b12f65b12bb151a1a36846", mod_consts.const_dict_fa591dc696b12f65b12bb151a1a36846);
assert(mod_consts_hash[26] == DEEP_HASH(tstate, mod_consts.const_dict_fa591dc696b12f65b12bb151a1a36846) && "mod_consts.const_dict_fa591dc696b12f65b12bb151a1a36846");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_85b825f4db9c19f334e726fd877a8261", mod_consts.const_dict_85b825f4db9c19f334e726fd877a8261);
assert(mod_consts_hash[27] == DEEP_HASH(tstate, mod_consts.const_dict_85b825f4db9c19f334e726fd877a8261) && "mod_consts.const_dict_85b825f4db9c19f334e726fd877a8261");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_main", mod_consts.const_str_plain_main);
assert(mod_consts_hash[28] == DEEP_HASH(tstate, mod_consts.const_str_plain_main) && "mod_consts.const_str_plain_main");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_07d0285b5381b31ce6c790ea1eb799a5", mod_consts.const_str_digest_07d0285b5381b31ce6c790ea1eb799a5);
assert(mod_consts_hash[29] == DEEP_HASH(tstate, mod_consts.const_str_digest_07d0285b5381b31ce6c790ea1eb799a5) && "mod_consts.const_str_digest_07d0285b5381b31ce6c790ea1eb799a5");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3", mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3);
assert(mod_consts_hash[30] == DEEP_HASH(tstate, mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3) && "mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple", mod_consts.const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple);
assert(mod_consts_hash[31] == DEEP_HASH(tstate, mod_consts.const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple) && "mod_consts.const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple", mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
assert(mod_consts_hash[32] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple) && "mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_name_tuple", mod_consts.const_tuple_str_plain_name_tuple);
assert(mod_consts_hash[33] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_name_tuple) && "mod_consts.const_tuple_str_plain_name_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple", mod_consts.const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple);
assert(mod_consts_hash[34] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple) && "mod_consts.const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
assert(mod_consts_hash[35] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple) && "mod_consts.const_tuple_str_plain_n_tuple");
}
#endif

// Helper to preserving module variables for Python3.11+
#if 8
#if PYTHON_VERSION >= 0x3c0
NUITKA_MAY_BE_UNUSED static uint32_t _Nuitka_PyDictKeys_GetVersionForCurrentState(PyInterpreterState *interp, PyDictKeysObject *dk)
{
    if (dk->dk_version != 0) {
        return dk->dk_version;
    }
    uint32_t result = Nuitka_PyInterpreterState_GetDictState(interp)->next_keys_version++;
    dk->dk_version = result;
    return result;
}
#elif PYTHON_VERSION >= 0x3b0
static uint32_t _Nuitka_next_dict_keys_version = 2;

NUITKA_MAY_BE_UNUSED static uint32_t _Nuitka_PyDictKeys_GetVersionForCurrentState(PyDictKeysObject *dk)
{
    if (dk->dk_version != 0) {
        return dk->dk_version;
    }
    uint32_t result = _Nuitka_next_dict_keys_version++;
    dk->dk_version = result;
    return result;
}
#endif
#endif

// Accessors to module variables.
static PyObject *module_var_accessor_gauntlet$BANNER(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_gauntlet->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_gauntlet->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_BANNER);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_gauntlet->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_BANNER);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_BANNER, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_BANNER);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_BANNER, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_BANNER);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_BANNER);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_BANNER);
    }

    return result;
}

static PyObject *module_var_accessor_gauntlet$SEED(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_gauntlet->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_gauntlet->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_SEED);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_gauntlet->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_SEED);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_SEED, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_SEED);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_SEED, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_SEED);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_SEED);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_SEED);
    }

    return result;
}

static PyObject *module_var_accessor_gauntlet$__annotations__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_gauntlet->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_gauntlet->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___annotations__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_gauntlet->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(const_str_plain___annotations__);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, const_str_plain___annotations__, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(const_str_plain___annotations__);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, const_str_plain___annotations__, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___annotations__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___annotations__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___annotations__);
    }

    return result;
}

static PyObject *module_var_accessor_gauntlet$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_gauntlet->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_gauntlet->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_gauntlet->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(const_str_plain___spec__);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, const_str_plain___spec__, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(const_str_plain___spec__);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, const_str_plain___spec__, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}

static PyObject *module_var_accessor_gauntlet$accumulate(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_gauntlet->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_gauntlet->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_accumulate);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_gauntlet->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_accumulate);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_accumulate, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_accumulate);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_accumulate, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_accumulate);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_accumulate);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_accumulate);
    }

    return result;
}

static PyObject *module_var_accessor_gauntlet$fib(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_gauntlet->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_gauntlet->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_gauntlet->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_fib);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_fib, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_fib);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_fib, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
    }

    return result;
}

static PyObject *module_var_accessor_gauntlet$greet(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_gauntlet->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_gauntlet->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_gauntlet->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_greet);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_greet, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_greet);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_greet, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
    }

    return result;
}

static PyObject *module_var_accessor_gauntlet$squares(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_gauntlet->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_gauntlet->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_squares);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_gauntlet->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_squares);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_squares, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_squares);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_squares, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_squares);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_squares);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_squares);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_2fab63f51e11368f46130fe39a339f37;
static PyCodeObject *code_objects_b00786ddab5578c16103565a2bca02c1;
static PyCodeObject *code_objects_85f2b6eb120fabc78470811a01d3941c;
static PyCodeObject *code_objects_fa3fe662b430fca32ed3fd90ad1d5a7b;
static PyCodeObject *code_objects_44e7e9a64fb167e501cc5352069825bc;
static PyCodeObject *code_objects_cb80a5521d7281270c0c3640da5d0ab9;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_07d0285b5381b31ce6c790ea1eb799a5); CHECK_OBJECT(module_filename_obj);
code_objects_2fab63f51e11368f46130fe39a339f37 = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_FUTURE_ANNOTATIONS, mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3, mod_consts.const_str_digest_d69802e95c91f8ac63217eb66261fba3, NULL, NULL, 0, 0, 0);
code_objects_b00786ddab5578c16103565a2bca02c1 = MAKE_CODE_OBJECT(module_filename_obj, 19, CO_OPTIMIZED | CO_NEWLOCALS | CO_FUTURE_ANNOTATIONS, mod_consts.const_str_plain_accumulate, mod_consts.const_str_plain_accumulate, mod_consts.const_tuple_747a6fc9bb95d22af842c1d15756c8c1_tuple, NULL, 2, 0, 0);
code_objects_85f2b6eb120fabc78470811a01d3941c = MAKE_CODE_OBJECT(module_filename_obj, 11, CO_OPTIMIZED | CO_NEWLOCALS | CO_FUTURE_ANNOTATIONS, mod_consts.const_str_plain_fib, mod_consts.const_str_plain_fib, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple, NULL, 1, 0, 0);
code_objects_fa3fe662b430fca32ed3fd90ad1d5a7b = MAKE_CODE_OBJECT(module_filename_obj, 7, CO_OPTIMIZED | CO_NEWLOCALS | CO_FUTURE_ANNOTATIONS, mod_consts.const_str_plain_greet, mod_consts.const_str_plain_greet, mod_consts.const_tuple_str_plain_name_tuple, NULL, 1, 0, 0);
code_objects_44e7e9a64fb167e501cc5352069825bc = MAKE_CODE_OBJECT(module_filename_obj, 30, CO_OPTIMIZED | CO_NEWLOCALS | CO_FUTURE_ANNOTATIONS, mod_consts.const_str_plain_main, mod_consts.const_str_plain_main, mod_consts.const_tuple_str_plain_label_str_plain_checksum_str_plain_table_tuple, NULL, 0, 0, 0);
code_objects_cb80a5521d7281270c0c3640da5d0ab9 = MAKE_CODE_OBJECT(module_filename_obj, 26, CO_OPTIMIZED | CO_NEWLOCALS | CO_FUTURE_ANNOTATIONS, mod_consts.const_str_plain_squares, mod_consts.const_str_plain_squares, mod_consts.const_tuple_str_plain_n_tuple, NULL, 1, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION_gauntlet$$$function__1_greet(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_gauntlet$$$function__2_fib(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_gauntlet$$$function__3_accumulate(PyThreadState *tstate, PyObject *defaults, PyObject *annotations);


static PyObject *MAKE_FUNCTION_gauntlet$$$function__4_squares(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_gauntlet$$$function__5_main(PyThreadState *tstate, PyObject *annotations);


// The module function definitions.
static PyObject *impl_gauntlet$$$function__1_greet(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_name = python_pars[0];
struct Nuitka_FrameObject *frame_frame_gauntlet$$$function__1_greet;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_gauntlet$$$function__1_greet = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_gauntlet$$$function__1_greet)) {
    Py_XDECREF(cache_frame_frame_gauntlet$$$function__1_greet);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_gauntlet$$$function__1_greet == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_gauntlet$$$function__1_greet = MAKE_FUNCTION_FRAME(tstate, code_objects_fa3fe662b430fca32ed3fd90ad1d5a7b, module_gauntlet, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_gauntlet$$$function__1_greet->m_type_description == NULL);
frame_frame_gauntlet$$$function__1_greet = cache_frame_frame_gauntlet$$$function__1_greet;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_gauntlet$$$function__1_greet);
assert(Py_REFCNT(frame_frame_gauntlet$$$function__1_greet) == 2);

// Framed code:
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
tmp_add_expr_left_1 = mod_consts.const_str_digest_b9584ea4ada6e1fe306f8b03aab3d4e9;
CHECK_OBJECT(par_name);
tmp_add_expr_right_1 = par_name;
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_UNICODE_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 8;
type_description_1 = "o";
    goto frame_exception_exit_1;
}
goto frame_return_exit_1;
}


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_return_exit_1:

// Put the previous frame back on top.
popFrameStack(tstate);

goto function_return_exit;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_gauntlet$$$function__1_greet, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_gauntlet$$$function__1_greet->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_gauntlet$$$function__1_greet, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_gauntlet$$$function__1_greet,
    type_description_1,
    par_name
);


// Release cached frame if used for exception.
if (frame_frame_gauntlet$$$function__1_greet == cache_frame_frame_gauntlet$$$function__1_greet) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_gauntlet$$$function__1_greet);
    cache_frame_frame_gauntlet$$$function__1_greet = NULL;
}

assertFrameObject(frame_frame_gauntlet$$$function__1_greet);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_name);
Py_DECREF(par_name);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_name);
Py_DECREF(par_name);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_gauntlet$$$function__2_fib(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_n = python_pars[0];
PyObject *var_a = NULL;
PyObject *var_b = NULL;
PyObject *var__ = NULL;
PyObject *tmp_for_loop_1__for_iterator = NULL;
PyObject *tmp_for_loop_1__iter_value = NULL;
PyObject *tmp_tuple_unpack_1__element_1 = NULL;
PyObject *tmp_tuple_unpack_1__element_2 = NULL;
PyObject *tmp_tuple_unpack_1__source_iter = NULL;
struct Nuitka_FrameObject *frame_frame_gauntlet$$$function__2_fib;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_3;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_3;
PyObject *tmp_return_value = NULL;
static struct Nuitka_FrameObject *cache_frame_frame_gauntlet$$$function__2_fib = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_4;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_4;

    // Actual function body.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = const_int_0;
{
    PyObject *old = var_a;
    var_a = tmp_assign_source_1;
    Py_INCREF(var_a);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = const_int_pos_1;
{
    PyObject *old = var_b;
    var_b = tmp_assign_source_2;
    Py_INCREF(var_b);
    Py_XDECREF(old);
}

}
// Tried code:
if (isFrameUnusable(cache_frame_frame_gauntlet$$$function__2_fib)) {
    Py_XDECREF(cache_frame_frame_gauntlet$$$function__2_fib);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_gauntlet$$$function__2_fib == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_gauntlet$$$function__2_fib = MAKE_FUNCTION_FRAME(tstate, code_objects_85f2b6eb120fabc78470811a01d3941c, module_gauntlet, sizeof(void *)+sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_gauntlet$$$function__2_fib->m_type_description == NULL);
frame_frame_gauntlet$$$function__2_fib = cache_frame_frame_gauntlet$$$function__2_fib;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_gauntlet$$$function__2_fib);
assert(Py_REFCNT(frame_frame_gauntlet$$$function__2_fib) == 2);

// Framed code:
{
PyObject *tmp_assign_source_3;
PyObject *tmp_iter_arg_1;
PyObject *tmp_xrange_low_1;
CHECK_OBJECT(par_n);
tmp_xrange_low_1 = par_n;
tmp_iter_arg_1 = BUILTIN_XRANGE1(tstate, tmp_xrange_low_1);
if (tmp_iter_arg_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 14;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
tmp_assign_source_3 = MAKE_ITERATOR(tstate, tmp_iter_arg_1);
CHECK_OBJECT(tmp_iter_arg_1);
Py_DECREF(tmp_iter_arg_1);
if (tmp_assign_source_3 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 14;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = tmp_for_loop_1__for_iterator;
    tmp_for_loop_1__for_iterator = tmp_assign_source_3;
    Py_XDECREF(old);
}

}
// Tried code:
loop_start_1:;
{
PyObject *tmp_next_source_1;
PyObject *tmp_assign_source_4;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
tmp_next_source_1 = tmp_for_loop_1__for_iterator;
tmp_assign_source_4 = ITERATOR_NEXT_ITERATOR(tmp_next_source_1);
if (tmp_assign_source_4 == NULL) {
    if (CHECK_AND_CLEAR_STOP_ITERATION_OCCURRED(tstate)) {

        goto loop_end_1;
    } else {

        FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
type_description_1 = "oooo";
exception_lineno = 14;
        goto try_except_handler_2;
    }
}

{
    PyObject *old = tmp_for_loop_1__iter_value;
    tmp_for_loop_1__iter_value = tmp_assign_source_4;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_5;
CHECK_OBJECT(tmp_for_loop_1__iter_value);
tmp_assign_source_5 = tmp_for_loop_1__iter_value;
{
    PyObject *old = var__;
    var__ = tmp_assign_source_5;
    Py_INCREF(var__);
    Py_XDECREF(old);
}

}
// Tried code:
{
PyObject *tmp_assign_source_6;
PyObject *tmp_iter_arg_2;
PyObject *tmp_tuple_element_1;
if (var_b == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, const_str_plain_b);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 15;
type_description_1 = "oooo";
    goto try_except_handler_3;
}

tmp_tuple_element_1 = var_b;
tmp_iter_arg_2 = MAKE_TUPLE_EMPTY(tstate, 2);
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
PyTuple_SET_ITEM0(tmp_iter_arg_2, 0, tmp_tuple_element_1);
if (var_a == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_a);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 15;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}

tmp_add_expr_left_1 = var_a;
if (var_b == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, const_str_plain_b);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 15;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}

tmp_add_expr_right_1 = var_b;
tmp_tuple_element_1 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 15;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}
PyTuple_SET_ITEM(tmp_iter_arg_2, 1, tmp_tuple_element_1);
}
goto tuple_build_no_exception_1;
// Exception handling pass through code for tuple_build:
tuple_build_exception_1:;
Py_DECREF(tmp_iter_arg_2);
goto try_except_handler_3;
// Finished with no exception for tuple_build:
tuple_build_no_exception_1:;
tmp_assign_source_6 = MAKE_ITERATOR_INFALLIBLE(tmp_iter_arg_2);
CHECK_OBJECT(tmp_iter_arg_2);
Py_DECREF(tmp_iter_arg_2);
assert(!(tmp_assign_source_6 == NULL));
{
    PyObject *old = tmp_tuple_unpack_1__source_iter;
    tmp_tuple_unpack_1__source_iter = tmp_assign_source_6;
    Py_XDECREF(old);
}

}
// Tried code:
{
PyObject *tmp_assign_source_7;
PyObject *tmp_unpack_1;
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
tmp_unpack_1 = tmp_tuple_unpack_1__source_iter;
tmp_assign_source_7 = UNPACK_NEXT(tstate, &exception_state, tmp_unpack_1, 0, 2);
if (tmp_assign_source_7 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 15;
type_description_1 = "oooo";
    goto try_except_handler_4;
}
{
    PyObject *old = tmp_tuple_unpack_1__element_1;
    tmp_tuple_unpack_1__element_1 = tmp_assign_source_7;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_unpack_2;
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
tmp_unpack_2 = tmp_tuple_unpack_1__source_iter;
tmp_assign_source_8 = UNPACK_NEXT(tstate, &exception_state, tmp_unpack_2, 1, 2);
if (tmp_assign_source_8 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 15;
type_description_1 = "oooo";
    goto try_except_handler_4;
}
{
    PyObject *old = tmp_tuple_unpack_1__element_2;
    tmp_tuple_unpack_1__element_2 = tmp_assign_source_8;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_iterator_name_1;
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
tmp_iterator_name_1 = tmp_tuple_unpack_1__source_iter;
tmp_result = UNPACK_ITERATOR_CHECK(tstate, &exception_state, tmp_iterator_name_1, 2);
if (tmp_result == false) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 15;
type_description_1 = "oooo";
    goto try_except_handler_4;
}
}
goto try_end_1;
// Exception handler code:
try_except_handler_4:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
Py_DECREF(tmp_tuple_unpack_1__source_iter);
tmp_tuple_unpack_1__source_iter = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto try_except_handler_3;
// End of try:
try_end_1:;
goto try_end_2;
// Exception handler code:
try_except_handler_3:;
exception_keeper_lineno_2 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_2 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_tuple_unpack_1__element_1);
tmp_tuple_unpack_1__element_1 = NULL;
Py_XDECREF(tmp_tuple_unpack_1__element_2);
tmp_tuple_unpack_1__element_2 = NULL;
// Re-raise.
exception_state = exception_keeper_name_2;
exception_lineno = exception_keeper_lineno_2;

goto try_except_handler_2;
// End of try:
try_end_2:;
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
Py_DECREF(tmp_tuple_unpack_1__source_iter);
tmp_tuple_unpack_1__source_iter = NULL;
{
PyObject *tmp_assign_source_9;
CHECK_OBJECT(tmp_tuple_unpack_1__element_1);
tmp_assign_source_9 = tmp_tuple_unpack_1__element_1;
{
    PyObject *old = var_a;
    var_a = tmp_assign_source_9;
    Py_INCREF(var_a);
    Py_XDECREF(old);
}

}
Py_XDECREF(tmp_tuple_unpack_1__element_1);
tmp_tuple_unpack_1__element_1 = NULL;

{
PyObject *tmp_assign_source_10;
CHECK_OBJECT(tmp_tuple_unpack_1__element_2);
tmp_assign_source_10 = tmp_tuple_unpack_1__element_2;
{
    PyObject *old = var_b;
    var_b = tmp_assign_source_10;
    Py_INCREF(var_b);
    Py_XDECREF(old);
}

}
Py_XDECREF(tmp_tuple_unpack_1__element_2);
tmp_tuple_unpack_1__element_2 = NULL;

if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 14;
type_description_1 = "oooo";
    goto try_except_handler_2;
}
goto loop_start_1;
loop_end_1:;
goto try_end_3;
// Exception handler code:
try_except_handler_2:;
exception_keeper_lineno_3 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_3 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_for_loop_1__iter_value);
tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
Py_DECREF(tmp_for_loop_1__for_iterator);
tmp_for_loop_1__for_iterator = NULL;
// Re-raise.
exception_state = exception_keeper_name_3;
exception_lineno = exception_keeper_lineno_3;

goto frame_exception_exit_1;
// End of try:
try_end_3:;
Py_XDECREF(tmp_for_loop_1__iter_value);
tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
Py_DECREF(tmp_for_loop_1__for_iterator);
tmp_for_loop_1__for_iterator = NULL;
if (var_a == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_a);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 16;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}

tmp_return_value = var_a;
Py_INCREF(tmp_return_value);
goto frame_return_exit_1;


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_return_exit_1:

// Put the previous frame back on top.
popFrameStack(tstate);

goto try_return_handler_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_gauntlet$$$function__2_fib, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_gauntlet$$$function__2_fib->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_gauntlet$$$function__2_fib, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_gauntlet$$$function__2_fib,
    type_description_1,
    par_n,
    var_a,
    var_b,
    var__
);


// Release cached frame if used for exception.
if (frame_frame_gauntlet$$$function__2_fib == cache_frame_frame_gauntlet$$$function__2_fib) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_gauntlet$$$function__2_fib);
    cache_frame_frame_gauntlet$$$function__2_fib = NULL;
}

assertFrameObject(frame_frame_gauntlet$$$function__2_fib);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
Py_XDECREF(var_a);
var_a = NULL;
Py_XDECREF(var_b);
var_b = NULL;
Py_XDECREF(var__);
var__ = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_4 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_4 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_a);
var_a = NULL;
Py_XDECREF(var_b);
var_b = NULL;
Py_XDECREF(var__);
var__ = NULL;
// Re-raise.
exception_state = exception_keeper_name_4;
exception_lineno = exception_keeper_lineno_4;

goto function_exception_exit;
// End of try:

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_n);
Py_DECREF(par_n);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_n);
Py_DECREF(par_n);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_gauntlet$$$function__3_accumulate(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_values = python_pars[0];
PyObject *par_factor = python_pars[1];
PyObject *var_total = NULL;
PyObject *var_value = NULL;
PyObject *tmp_for_loop_1__for_iterator = NULL;
PyObject *tmp_for_loop_1__iter_value = NULL;
struct Nuitka_FrameObject *frame_frame_gauntlet$$$function__3_accumulate;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
PyObject *tmp_return_value = NULL;
static struct Nuitka_FrameObject *cache_frame_frame_gauntlet$$$function__3_accumulate = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;

    // Actual function body.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = const_int_0;
{
    PyObject *old = var_total;
    var_total = tmp_assign_source_1;
    Py_INCREF(var_total);
    Py_XDECREF(old);
}

}
// Tried code:
if (isFrameUnusable(cache_frame_frame_gauntlet$$$function__3_accumulate)) {
    Py_XDECREF(cache_frame_frame_gauntlet$$$function__3_accumulate);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_gauntlet$$$function__3_accumulate == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_gauntlet$$$function__3_accumulate = MAKE_FUNCTION_FRAME(tstate, code_objects_b00786ddab5578c16103565a2bca02c1, module_gauntlet, sizeof(void *)+sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_gauntlet$$$function__3_accumulate->m_type_description == NULL);
frame_frame_gauntlet$$$function__3_accumulate = cache_frame_frame_gauntlet$$$function__3_accumulate;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_gauntlet$$$function__3_accumulate);
assert(Py_REFCNT(frame_frame_gauntlet$$$function__3_accumulate) == 2);

// Framed code:
{
PyObject *tmp_assign_source_2;
PyObject *tmp_iter_arg_1;
CHECK_OBJECT(par_values);
tmp_iter_arg_1 = par_values;
tmp_assign_source_2 = MAKE_ITERATOR(tstate, tmp_iter_arg_1);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 21;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = tmp_for_loop_1__for_iterator;
    tmp_for_loop_1__for_iterator = tmp_assign_source_2;
    Py_XDECREF(old);
}

}
// Tried code:
loop_start_1:;
{
PyObject *tmp_next_source_1;
PyObject *tmp_assign_source_3;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
tmp_next_source_1 = tmp_for_loop_1__for_iterator;
tmp_assign_source_3 = ITERATOR_NEXT(tmp_next_source_1);
if (tmp_assign_source_3 == NULL) {
    if (CHECK_AND_CLEAR_STOP_ITERATION_OCCURRED(tstate)) {

        goto loop_end_1;
    } else {

        FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
type_description_1 = "oooo";
exception_lineno = 21;
        goto try_except_handler_2;
    }
}

{
    PyObject *old = tmp_for_loop_1__iter_value;
    tmp_for_loop_1__iter_value = tmp_assign_source_3;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_4;
CHECK_OBJECT(tmp_for_loop_1__iter_value);
tmp_assign_source_4 = tmp_for_loop_1__iter_value;
{
    PyObject *old = var_value;
    var_value = tmp_assign_source_4;
    Py_INCREF(var_value);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
PyObject *tmp_mult_expr_left_1;
PyObject *tmp_mult_expr_right_1;
if (var_total == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_total);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 22;
type_description_1 = "oooo";
    goto try_except_handler_2;
}

tmp_add_expr_left_1 = var_total;
CHECK_OBJECT(var_value);
tmp_mult_expr_left_1 = var_value;
if (par_factor == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_factor);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 22;
type_description_1 = "oooo";
    goto try_except_handler_2;
}

tmp_mult_expr_right_1 = par_factor;
tmp_add_expr_right_1 = BINARY_OPERATION_MULT_OBJECT_OBJECT_OBJECT(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
if (tmp_add_expr_right_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 22;
type_description_1 = "oooo";
    goto try_except_handler_2;
}
tmp_assign_source_5 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
CHECK_OBJECT(tmp_add_expr_right_1);
Py_DECREF(tmp_add_expr_right_1);
if (tmp_assign_source_5 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 22;
type_description_1 = "oooo";
    goto try_except_handler_2;
}
{
    PyObject *old = var_total;
    var_total = tmp_assign_source_5;
    Py_XDECREF(old);
}

}
if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 21;
type_description_1 = "oooo";
    goto try_except_handler_2;
}
goto loop_start_1;
loop_end_1:;
goto try_end_1;
// Exception handler code:
try_except_handler_2:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_for_loop_1__iter_value);
tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
Py_DECREF(tmp_for_loop_1__for_iterator);
tmp_for_loop_1__for_iterator = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto frame_exception_exit_1;
// End of try:
try_end_1:;
Py_XDECREF(tmp_for_loop_1__iter_value);
tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
Py_DECREF(tmp_for_loop_1__for_iterator);
tmp_for_loop_1__for_iterator = NULL;
if (var_total == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_total);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 23;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}

tmp_return_value = var_total;
Py_INCREF(tmp_return_value);
goto frame_return_exit_1;


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_return_exit_1:

// Put the previous frame back on top.
popFrameStack(tstate);

goto try_return_handler_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_gauntlet$$$function__3_accumulate, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_gauntlet$$$function__3_accumulate->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_gauntlet$$$function__3_accumulate, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_gauntlet$$$function__3_accumulate,
    type_description_1,
    par_values,
    par_factor,
    var_total,
    var_value
);


// Release cached frame if used for exception.
if (frame_frame_gauntlet$$$function__3_accumulate == cache_frame_frame_gauntlet$$$function__3_accumulate) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_gauntlet$$$function__3_accumulate);
    cache_frame_frame_gauntlet$$$function__3_accumulate = NULL;
}

assertFrameObject(frame_frame_gauntlet$$$function__3_accumulate);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
Py_XDECREF(var_total);
var_total = NULL;
Py_XDECREF(var_value);
var_value = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_2 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_2 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_total);
var_total = NULL;
Py_XDECREF(var_value);
var_value = NULL;
// Re-raise.
exception_state = exception_keeper_name_2;
exception_lineno = exception_keeper_lineno_2;

goto function_exception_exit;
// End of try:

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_values);
Py_DECREF(par_values);
CHECK_OBJECT(par_factor);
Py_DECREF(par_factor);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_values);
Py_DECREF(par_values);
CHECK_OBJECT(par_factor);
Py_DECREF(par_factor);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_gauntlet$$$function__4_squares(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_n = python_pars[0];
PyObject *outline_0_var_i = NULL;
PyObject *tmp_dictcontraction_1__$0 = NULL;
PyObject *tmp_dictcontraction_1__contraction = NULL;
PyObject *tmp_dictcontraction_1__iter_value_0 = NULL;
struct Nuitka_FrameObject *frame_frame_gauntlet$$$function__4_squares;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
int tmp_res;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
static struct Nuitka_FrameObject *cache_frame_frame_gauntlet$$$function__4_squares = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_gauntlet$$$function__4_squares)) {
    Py_XDECREF(cache_frame_frame_gauntlet$$$function__4_squares);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_gauntlet$$$function__4_squares == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_gauntlet$$$function__4_squares = MAKE_FUNCTION_FRAME(tstate, code_objects_cb80a5521d7281270c0c3640da5d0ab9, module_gauntlet, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_gauntlet$$$function__4_squares->m_type_description == NULL);
frame_frame_gauntlet$$$function__4_squares = cache_frame_frame_gauntlet$$$function__4_squares;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_gauntlet$$$function__4_squares);
assert(Py_REFCNT(frame_frame_gauntlet$$$function__4_squares) == 2);

// Framed code:
// Tried code:
{
PyObject *tmp_assign_source_1;
PyObject *tmp_iter_arg_1;
PyObject *tmp_xrange_low_1;
CHECK_OBJECT(par_n);
tmp_xrange_low_1 = par_n;
tmp_iter_arg_1 = BUILTIN_XRANGE1(tstate, tmp_xrange_low_1);
if (tmp_iter_arg_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 27;
type_description_1 = "o";
    goto try_except_handler_1;
}
tmp_assign_source_1 = MAKE_ITERATOR(tstate, tmp_iter_arg_1);
CHECK_OBJECT(tmp_iter_arg_1);
Py_DECREF(tmp_iter_arg_1);
if (tmp_assign_source_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 27;
type_description_1 = "o";
    goto try_except_handler_1;
}
{
    PyObject *old = tmp_dictcontraction_1__$0;
    tmp_dictcontraction_1__$0 = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = MAKE_DICT_EMPTY(tstate);
{
    PyObject *old = tmp_dictcontraction_1__contraction;
    tmp_dictcontraction_1__contraction = tmp_assign_source_2;
    Py_XDECREF(old);
}

}
// Tried code:
loop_start_1:;
{
PyObject *tmp_next_source_1;
PyObject *tmp_assign_source_3;
CHECK_OBJECT(tmp_dictcontraction_1__$0);
tmp_next_source_1 = tmp_dictcontraction_1__$0;
tmp_assign_source_3 = ITERATOR_NEXT_ITERATOR(tmp_next_source_1);
if (tmp_assign_source_3 == NULL) {
    if (CHECK_AND_CLEAR_STOP_ITERATION_OCCURRED(tstate)) {

        goto loop_end_1;
    } else {

        FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
type_description_1 = "o";
exception_lineno = 27;
        goto try_except_handler_2;
    }
}

{
    PyObject *old = tmp_dictcontraction_1__iter_value_0;
    tmp_dictcontraction_1__iter_value_0 = tmp_assign_source_3;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_4;
CHECK_OBJECT(tmp_dictcontraction_1__iter_value_0);
tmp_assign_source_4 = tmp_dictcontraction_1__iter_value_0;
{
    PyObject *old = outline_0_var_i;
    outline_0_var_i = tmp_assign_source_4;
    Py_INCREF(outline_0_var_i);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_dictset38_key_1;
PyObject *tmp_dictset38_value_1;
PyObject *tmp_mult_expr_left_1;
PyObject *tmp_mult_expr_right_1;
PyObject *tmp_dictset38_dict_1;
CHECK_OBJECT(outline_0_var_i);
tmp_dictset38_key_1 = outline_0_var_i;
CHECK_OBJECT(outline_0_var_i);
tmp_mult_expr_left_1 = outline_0_var_i;
CHECK_OBJECT(outline_0_var_i);
tmp_mult_expr_right_1 = outline_0_var_i;
tmp_dictset38_value_1 = BINARY_OPERATION_MULT_OBJECT_OBJECT_OBJECT(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
if (tmp_dictset38_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 27;
type_description_1 = "o";
    goto try_except_handler_2;
}
CHECK_OBJECT(tmp_dictcontraction_1__contraction);
tmp_dictset38_dict_1 = tmp_dictcontraction_1__contraction;
assert(PyDict_CheckExact(tmp_dictset38_dict_1));
tmp_res = PyDict_SetItem(tmp_dictset38_dict_1, tmp_dictset38_key_1, tmp_dictset38_value_1);

CHECK_OBJECT(tmp_dictset38_value_1);
Py_DECREF(tmp_dictset38_value_1);
if (tmp_res != 0) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 27;
type_description_1 = "o";
    goto try_except_handler_2;
}
}
if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 27;
type_description_1 = "o";
    goto try_except_handler_2;
}
goto loop_start_1;
loop_end_1:;
CHECK_OBJECT(tmp_dictcontraction_1__contraction);
tmp_return_value = tmp_dictcontraction_1__contraction;
Py_INCREF(tmp_return_value);
goto try_return_handler_2;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_2:;
CHECK_OBJECT(tmp_dictcontraction_1__$0);
CHECK_OBJECT(tmp_dictcontraction_1__$0);
Py_DECREF(tmp_dictcontraction_1__$0);
tmp_dictcontraction_1__$0 = NULL;
CHECK_OBJECT(tmp_dictcontraction_1__contraction);
CHECK_OBJECT(tmp_dictcontraction_1__contraction);
Py_DECREF(tmp_dictcontraction_1__contraction);
tmp_dictcontraction_1__contraction = NULL;
Py_XDECREF(tmp_dictcontraction_1__iter_value_0);
tmp_dictcontraction_1__iter_value_0 = NULL;
goto try_return_handler_1;
// Exception handler code:
try_except_handler_2:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(tmp_dictcontraction_1__$0);
CHECK_OBJECT(tmp_dictcontraction_1__$0);
Py_DECREF(tmp_dictcontraction_1__$0);
tmp_dictcontraction_1__$0 = NULL;
CHECK_OBJECT(tmp_dictcontraction_1__contraction);
CHECK_OBJECT(tmp_dictcontraction_1__contraction);
Py_DECREF(tmp_dictcontraction_1__contraction);
tmp_dictcontraction_1__contraction = NULL;
Py_XDECREF(tmp_dictcontraction_1__iter_value_0);
tmp_dictcontraction_1__iter_value_0 = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto try_except_handler_1;
// End of try:
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
Py_XDECREF(outline_0_var_i);
outline_0_var_i = NULL;
goto outline_result_1;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_2 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_2 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(outline_0_var_i);
outline_0_var_i = NULL;
// Re-raise.
exception_state = exception_keeper_name_2;
exception_lineno = exception_keeper_lineno_2;

goto outline_exception_1;
// End of try:
NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;
outline_exception_1:;
exception_lineno = 27;
goto frame_exception_exit_1;
outline_result_1:;
goto frame_return_exit_1;


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_return_exit_1:

// Put the previous frame back on top.
popFrameStack(tstate);

goto function_return_exit;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_gauntlet$$$function__4_squares, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_gauntlet$$$function__4_squares->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_gauntlet$$$function__4_squares, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_gauntlet$$$function__4_squares,
    type_description_1,
    par_n
);


// Release cached frame if used for exception.
if (frame_frame_gauntlet$$$function__4_squares == cache_frame_frame_gauntlet$$$function__4_squares) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_gauntlet$$$function__4_squares);
    cache_frame_frame_gauntlet$$$function__4_squares = NULL;
}

assertFrameObject(frame_frame_gauntlet$$$function__4_squares);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_n);
Py_DECREF(par_n);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_n);
Py_DECREF(par_n);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_gauntlet$$$function__5_main(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *var_label = NULL;
PyObject *var_checksum = NULL;
PyObject *var_table = NULL;
struct Nuitka_FrameObject *frame_frame_gauntlet$$$function__5_main;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
PyObject *tmp_return_value = NULL;
static struct Nuitka_FrameObject *cache_frame_frame_gauntlet$$$function__5_main = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;

    // Actual function body.
// Tried code:
if (isFrameUnusable(cache_frame_frame_gauntlet$$$function__5_main)) {
    Py_XDECREF(cache_frame_frame_gauntlet$$$function__5_main);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_gauntlet$$$function__5_main == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_gauntlet$$$function__5_main = MAKE_FUNCTION_FRAME(tstate, code_objects_44e7e9a64fb167e501cc5352069825bc, module_gauntlet, sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_gauntlet$$$function__5_main->m_type_description == NULL);
frame_frame_gauntlet$$$function__5_main = cache_frame_frame_gauntlet$$$function__5_main;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_gauntlet$$$function__5_main);
assert(Py_REFCNT(frame_frame_gauntlet$$$function__5_main) == 2);

// Framed code:
{
PyObject *tmp_assign_source_1;
PyObject *tmp_called_value_1;
PyObject *tmp_args_element_value_1;
tmp_called_value_1 = module_var_accessor_gauntlet$greet(tstate);
if (unlikely(tmp_called_value_1 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_greet);
}

if (tmp_called_value_1 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 31;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
tmp_args_element_value_1 = module_var_accessor_gauntlet$BANNER(tstate);
if (unlikely(tmp_args_element_value_1 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_BANNER);
}

if (tmp_args_element_value_1 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 31;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
frame_frame_gauntlet$$$function__5_main->m_frame.f_lineno = 31;
tmp_assign_source_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_1, tmp_args_element_value_1);
if (tmp_assign_source_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 31;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = var_label;
    var_label = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_2;
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
PyObject *tmp_add_expr_left_2;
PyObject *tmp_add_expr_right_2;
PyObject *tmp_called_value_2;
PyObject *tmp_called_value_3;
PyObject *tmp_call_arg_element_1;
tmp_called_value_2 = module_var_accessor_gauntlet$fib(tstate);
if (unlikely(tmp_called_value_2 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_fib);
}

if (tmp_called_value_2 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 32;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
frame_frame_gauntlet$$$function__5_main->m_frame.f_lineno = 32;
tmp_add_expr_left_2 = CALL_FUNCTION_WITH_POS_ARGS1(tstate, tmp_called_value_2, mod_consts.const_tuple_int_pos_20_tuple);

if (tmp_add_expr_left_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 32;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
tmp_called_value_3 = module_var_accessor_gauntlet$accumulate(tstate);
if (unlikely(tmp_called_value_3 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_accumulate);
}

if (tmp_called_value_3 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));

Py_DECREF(tmp_add_expr_left_2);

exception_lineno = 32;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
tmp_call_arg_element_1 = MAKE_LIST3(tstate, mod_consts.const_int_pos_3,mod_consts.const_int_pos_5,mod_consts.const_int_pos_7);
frame_frame_gauntlet$$$function__5_main->m_frame.f_lineno = 32;
tmp_add_expr_right_2 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_3, tmp_call_arg_element_1);
CHECK_OBJECT(tmp_call_arg_element_1);
Py_DECREF(tmp_call_arg_element_1);
if (tmp_add_expr_right_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
Py_DECREF(tmp_add_expr_left_2);

exception_lineno = 32;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
tmp_add_expr_left_1 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_2, tmp_add_expr_right_2);
CHECK_OBJECT(tmp_add_expr_left_2);
Py_DECREF(tmp_add_expr_left_2);
CHECK_OBJECT(tmp_add_expr_right_2);
Py_DECREF(tmp_add_expr_right_2);
if (tmp_add_expr_left_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 32;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
tmp_add_expr_right_1 = module_var_accessor_gauntlet$SEED(tstate);
if (unlikely(tmp_add_expr_right_1 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_SEED);
}

if (tmp_add_expr_right_1 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));

Py_DECREF(tmp_add_expr_left_1);

exception_lineno = 32;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
tmp_assign_source_2 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
CHECK_OBJECT(tmp_add_expr_left_1);
Py_DECREF(tmp_add_expr_left_1);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 32;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = var_checksum;
    var_checksum = tmp_assign_source_2;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_3;
PyObject *tmp_called_value_4;
tmp_called_value_4 = module_var_accessor_gauntlet$squares(tstate);
if (unlikely(tmp_called_value_4 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_squares);
}

if (tmp_called_value_4 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 33;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
frame_frame_gauntlet$$$function__5_main->m_frame.f_lineno = 33;
tmp_assign_source_3 = CALL_FUNCTION_WITH_POS_ARGS1(tstate, tmp_called_value_4, mod_consts.const_tuple_int_pos_4_tuple);

if (tmp_assign_source_3 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 33;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = var_table;
    var_table = tmp_assign_source_3;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_add_expr_left_3;
PyObject *tmp_add_expr_right_3;
PyObject *tmp_add_expr_left_4;
PyObject *tmp_add_expr_right_4;
PyObject *tmp_len_arg_1;
PyObject *tmp_len_arg_2;
CHECK_OBJECT(var_checksum);
tmp_add_expr_left_4 = var_checksum;
CHECK_OBJECT(var_label);
tmp_len_arg_1 = var_label;
tmp_add_expr_right_4 = BUILTIN_LEN(tstate, tmp_len_arg_1);
if (tmp_add_expr_right_4 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 34;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
tmp_add_expr_left_3 = BINARY_OPERATION_ADD_OBJECT_OBJECT_LONG(tmp_add_expr_left_4, tmp_add_expr_right_4);
CHECK_OBJECT(tmp_add_expr_right_4);
Py_DECREF(tmp_add_expr_right_4);
if (tmp_add_expr_left_3 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 34;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
CHECK_OBJECT(var_table);
tmp_len_arg_2 = var_table;
tmp_add_expr_right_3 = BUILTIN_LEN(tstate, tmp_len_arg_2);
if (tmp_add_expr_right_3 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
Py_DECREF(tmp_add_expr_left_3);

exception_lineno = 34;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_LONG(tmp_add_expr_left_3, tmp_add_expr_right_3);
CHECK_OBJECT(tmp_add_expr_left_3);
Py_DECREF(tmp_add_expr_left_3);
CHECK_OBJECT(tmp_add_expr_right_3);
Py_DECREF(tmp_add_expr_right_3);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 34;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
goto frame_return_exit_1;
}


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_return_exit_1:

// Put the previous frame back on top.
popFrameStack(tstate);

goto try_return_handler_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_gauntlet$$$function__5_main, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_gauntlet$$$function__5_main->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_gauntlet$$$function__5_main, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_gauntlet$$$function__5_main,
    type_description_1,
    var_label,
    var_checksum,
    var_table
);


// Release cached frame if used for exception.
if (frame_frame_gauntlet$$$function__5_main == cache_frame_frame_gauntlet$$$function__5_main) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_gauntlet$$$function__5_main);
    cache_frame_frame_gauntlet$$$function__5_main = NULL;
}

assertFrameObject(frame_frame_gauntlet$$$function__5_main);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
CHECK_OBJECT(var_label);
CHECK_OBJECT(var_label);
Py_DECREF(var_label);
var_label = NULL;
CHECK_OBJECT(var_checksum);
CHECK_OBJECT(var_checksum);
Py_DECREF(var_checksum);
var_checksum = NULL;
CHECK_OBJECT(var_table);
CHECK_OBJECT(var_table);
Py_DECREF(var_table);
var_table = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_label);
var_label = NULL;
Py_XDECREF(var_checksum);
var_checksum = NULL;
Py_XDECREF(var_table);
var_table = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto function_exception_exit;
// End of try:

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:

    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.


   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}



static PyObject *MAKE_FUNCTION_gauntlet$$$function__1_greet(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_gauntlet$$$function__1_greet,
        mod_consts.const_str_plain_greet,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_fa3fe662b430fca32ed3fd90ad1d5a7b,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_gauntlet,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_gauntlet$$$function__2_fib(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_gauntlet$$$function__2_fib,
        mod_consts.const_str_plain_fib,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_85f2b6eb120fabc78470811a01d3941c,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_gauntlet,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_gauntlet$$$function__3_accumulate(PyThreadState *tstate, PyObject *defaults, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_gauntlet$$$function__3_accumulate,
        mod_consts.const_str_plain_accumulate,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_b00786ddab5578c16103565a2bca02c1,
        defaults,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_gauntlet,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_gauntlet$$$function__4_squares(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_gauntlet$$$function__4_squares,
        mod_consts.const_str_plain_squares,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_cb80a5521d7281270c0c3640da5d0ab9,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_gauntlet,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_gauntlet$$$function__5_main(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_gauntlet$$$function__5_main,
        mod_consts.const_str_plain_main,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_44e7e9a64fb167e501cc5352069825bc,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_gauntlet,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}


extern void _initCompiledCellType();
extern void _initCompiledGeneratorType();
extern void _initCompiledFunctionType();
extern void _initCompiledMethodType();
extern void _initCompiledFrameType();

extern PyTypeObject Nuitka_Loader_Type;

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
// Provide a way to create find a function via its C code and create it back
// in another process, useful for multiprocessing extensions like dill
extern void registerDillPluginTables(PyThreadState *tstate, char const *module_name, PyMethodDef *reduce_compiled_function, PyMethodDef *create_compiled_function);

static function_impl_code const function_table_gauntlet[] = {
impl_gauntlet$$$function__1_greet,
impl_gauntlet$$$function__2_fib,
impl_gauntlet$$$function__3_accumulate,
impl_gauntlet$$$function__4_squares,
impl_gauntlet$$$function__5_main,
    NULL
};

static PyObject *_reduce_compiled_function(PyObject *self, PyObject *args, PyObject *kwds) {
    PyObject *func;

    if (!PyArg_ParseTuple(args, "O:reduce_compiled_function", &func, NULL)) {
        return NULL;
    }

    if (Nuitka_Function_Check(func) == false) {
        PyThreadState *tstate = PyThreadState_GET();

        SET_CURRENT_EXCEPTION_TYPE0_STR(tstate, PyExc_TypeError, "not a compiled function");
        return NULL;
    }

    struct Nuitka_FunctionObject *function = (struct Nuitka_FunctionObject *)func;

    return Nuitka_Function_GetFunctionState(function, function_table_gauntlet);
}

static PyMethodDef _method_def_reduce_compiled_function = {"reduce_compiled_function", (PyCFunction)_reduce_compiled_function,
                                                           METH_VARARGS, NULL};


static PyObject *_create_compiled_function(PyObject *self, PyObject *args, PyObject *kwds) {
    CHECK_OBJECT_DEEP(args);

    PyObject *function_index;
    PyObject *code_object_desc;
    PyObject *defaults;
    PyObject *kw_defaults;
    PyObject *doc;
    PyObject *constant_return_value;
    PyObject *function_qualname;
    PyObject *closure;
    PyObject *annotations;
    PyObject *func_dict;

    if (!PyArg_ParseTuple(args, "OOOOOOOOOO:create_compiled_function", &function_index, &code_object_desc, &defaults, &kw_defaults, &doc, &constant_return_value, &function_qualname, &closure, &annotations, &func_dict, NULL)) {
        return NULL;
    }

    return (PyObject *)Nuitka_Function_CreateFunctionViaCodeIndex(
        module_gauntlet,
        function_qualname,
        function_index,
        code_object_desc,
        constant_return_value,
        defaults,
        kw_defaults,
        doc,
        closure,
        annotations,
        func_dict,
        function_table_gauntlet,
        sizeof(function_table_gauntlet) / sizeof(function_impl_code)
    );
}

static PyMethodDef _method_def_create_compiled_function = {
    "create_compiled_function",
    (PyCFunction)_create_compiled_function,
    METH_VARARGS, NULL
};


#endif

// Actual name might be different when loaded as a package.
#if _NUITKA_MODULE_MODE && 1
static char const *module_full_name = "gauntlet";
#endif

// Internal entry point for module code.
PyObject *module_code_gauntlet(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("gauntlet");

    // Store the module for future use.
    module_gauntlet = module;

    moduledict_gauntlet = MODULE_DICT(module_gauntlet);

    // Modules can be loaded again in case of errors, avoid the init being done again.
    static bool init_done = false;

    if (init_done == false) {
#if _NUITKA_MODULE_MODE && 1
        // In case of an extension module loaded into a process, we need to call
        // initialization here because that's the first and potentially only time
        // we are going called.
#if PYTHON_VERSION > 0x350 && !defined(_NUITKA_EXPERIMENTAL_DISABLE_ALLOCATORS)
        initNuitkaAllocators();
#endif
        // Initialize the constant values used.
        _initBuiltinModule(tstate);

        PyObject *real_module_name = PyObject_GetAttrString(module, "__name__");
        CHECK_OBJECT(real_module_name);
        module_full_name = strdup(Nuitka_String_AsString(real_module_name));

        createGlobalConstants(tstate, real_module_name);

        /* Initialize the compiled types of Nuitka. */
        _initCompiledCellType();
        _initCompiledGeneratorType();
        _initCompiledFunctionType();
        _initCompiledMethodType();
        _initCompiledFrameType();

        _initSlotCompare();
#if PYTHON_VERSION >= 0x270
        _initSlotIterNext();
#endif

        patchTypeComparison();

        // Enable meta path based loader if not already done.
#ifdef _NUITKA_TRACE
        PRINT_STRING("gauntlet: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("gauntlet: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("gauntlet: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "gauntlet" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initgauntlet\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___name__);
            module_name_c = Nuitka_String_AsString(module_name);
        }

        registerDillPluginTables(tstate, module_name_c, &_method_def_reduce_compiled_function, &_method_def_create_compiled_function);
    }
#endif

    // For Python 3.11 standalone modules, package "__path__" is inserted by the
    // loader before module code runs. Pre-seed "__compiled__" for non-packages
    // to keep their dangerous dict slots aligned with packages.
#if PYTHON_VERSION >= 0x3b0 && PYTHON_VERSION < 0x3c0 && _NUITKA_STANDALONE_MODE && !0
    UPDATE_STRING_DICT0(
        moduledict_gauntlet,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_gauntlet,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_gauntlet,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_gauntlet,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_gauntlet,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_gauntlet);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_gauntlet);
        Py_DECREF(_spec_from_module);

        // We can assume this to never fail, or else we are in trouble anyway.
        // CHECK_OBJECT(spec_value);

        if (spec_value == NULL) {
            PyErr_PrintEx(0);
            abort();
        }

        // Mark the execution in the "__spec__" value.
        SET_ATTRIBUTE(tstate, spec_value, const_str_plain__initializing, Py_True);

#if _NUITKA_MODULE_MODE && 1 && 0 >= 0
        // Set our loader object in the "__spec__" value.
        SET_ATTRIBUTE(tstate, spec_value, const_str_plain_loader, module_loader);
#endif

        UPDATE_STRING_DICT1(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_gauntlet;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
PyObject *tmp_dictset_value;
PyObject *tmp_dictset_dict;
PyObject *tmp_dictset_key;
int tmp_res;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_gauntlet = MAKE_MODULE_FRAME(code_objects_2fab63f51e11368f46130fe39a339f37, module_gauntlet);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_gauntlet);
assert(Py_REFCNT(frame_frame_gauntlet) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_gauntlet$__spec__(tstate);
assert(!(tmp_ass_attr_target_1 == NULL));
tmp_result = SET_ATTRIBUTE(tstate, tmp_ass_attr_target_1, mod_consts.const_str_plain_origin, tmp_ass_attr_value_1);
if (tmp_result == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto frame_exception_exit_1;
}
}
{
PyObject *tmp_ass_attr_value_2;
PyObject *tmp_ass_attr_target_2;
tmp_ass_attr_value_2 = Py_True;
tmp_ass_attr_target_2 = module_var_accessor_gauntlet$__spec__(tstate);
assert(!(tmp_ass_attr_target_2 == NULL));
tmp_result = SET_ATTRIBUTE(tstate, tmp_ass_attr_target_2, mod_consts.const_str_plain_has_location, tmp_ass_attr_value_2);
if (tmp_result == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto frame_exception_exit_1;
}
}
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
tmp_assign_source_5 = MAKE_DICT_EMPTY(tstate);
UPDATE_STRING_DICT1(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___annotations__, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
{
    PyObject *hard_module = IMPORT_HARD___FUTURE__();
    tmp_assign_source_6 = LOOKUP_ATTRIBUTE(tstate, hard_module, mod_consts.const_str_plain_annotations);
}
assert(!(tmp_assign_source_6 == NULL));
UPDATE_STRING_DICT1(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_annotations, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;
tmp_assign_source_7 = mod_consts.const_str_digest_17758251adb19c3d0df3013b5efd0f18;
UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_BANNER, tmp_assign_source_7);
}
tmp_dictset_value = mod_consts.const_str_plain_str;
tmp_dictset_dict = module_var_accessor_gauntlet$__annotations__(tstate);
assert(!(tmp_dictset_dict == NULL));
tmp_dictset_key = mod_consts.const_str_plain_BANNER;
assert(PyDict_CheckExact(tmp_dictset_dict));
tmp_res = PyDict_SetItem(tmp_dictset_dict, tmp_dictset_key, tmp_dictset_value);

assert(!(tmp_res != 0));
{
PyObject *tmp_assign_source_8;
tmp_assign_source_8 = mod_consts.const_int_pos_1337;
UPDATE_STRING_DICT0(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_SEED, tmp_assign_source_8);
}
{
PyObject *tmp_ass_subvalue_1;
PyObject *tmp_ass_subscribed_1;
PyObject *tmp_ass_subscript_1;
tmp_ass_subvalue_1 = mod_consts.const_str_plain_int;
tmp_ass_subscribed_1 = module_var_accessor_gauntlet$__annotations__(tstate);
if (unlikely(tmp_ass_subscribed_1 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, const_str_plain___annotations__);
}

if (tmp_ass_subscribed_1 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 4;

    goto frame_exception_exit_1;
}
tmp_ass_subscript_1 = mod_consts.const_str_plain_SEED;
tmp_result = SET_SUBSCRIPT(tstate, tmp_ass_subscribed_1, tmp_ass_subscript_1, tmp_ass_subvalue_1);
if (tmp_result == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 4;

    goto frame_exception_exit_1;
}
}


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_gauntlet, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_gauntlet->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_gauntlet, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_gauntlet);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
{
PyObject *tmp_assign_source_9;
PyObject *tmp_annotations_1;
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_e64cc0c4534221dfd66afecde3b815f7);

tmp_assign_source_9 = MAKE_FUNCTION_gauntlet$$$function__1_greet(tstate, tmp_annotations_1);

UPDATE_STRING_DICT1(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_greet, tmp_assign_source_9);
}
{
PyObject *tmp_assign_source_10;
PyObject *tmp_annotations_2;
tmp_annotations_2 = DICT_COPY(tstate, mod_consts.const_dict_6b4ef39d483624f4dfea54e4093b9d1a);

tmp_assign_source_10 = MAKE_FUNCTION_gauntlet$$$function__2_fib(tstate, tmp_annotations_2);

UPDATE_STRING_DICT1(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_fib, tmp_assign_source_10);
}
{
PyObject *tmp_assign_source_11;
PyObject *tmp_defaults_1;
PyObject *tmp_annotations_3;
tmp_defaults_1 = mod_consts.const_tuple_int_pos_2_tuple;
tmp_annotations_3 = DICT_COPY(tstate, mod_consts.const_dict_714c8f4d2e45bcee12b901fe97bd646f);
Py_INCREF(tmp_defaults_1);

tmp_assign_source_11 = MAKE_FUNCTION_gauntlet$$$function__3_accumulate(tstate, tmp_defaults_1, tmp_annotations_3);

UPDATE_STRING_DICT1(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_accumulate, tmp_assign_source_11);
}
{
PyObject *tmp_assign_source_12;
PyObject *tmp_annotations_4;
tmp_annotations_4 = DICT_COPY(tstate, mod_consts.const_dict_fa591dc696b12f65b12bb151a1a36846);

tmp_assign_source_12 = MAKE_FUNCTION_gauntlet$$$function__4_squares(tstate, tmp_annotations_4);

UPDATE_STRING_DICT1(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_squares, tmp_assign_source_12);
}
{
PyObject *tmp_assign_source_13;
PyObject *tmp_annotations_5;
tmp_annotations_5 = DICT_COPY(tstate, mod_consts.const_dict_85b825f4db9c19f334e726fd877a8261);

tmp_assign_source_13 = MAKE_FUNCTION_gauntlet$$$function__5_main(tstate, tmp_annotations_5);

UPDATE_STRING_DICT1(moduledict_gauntlet, (Nuitka_StringObject *)mod_consts.const_str_plain_main, tmp_assign_source_13);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("gauntlet", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "gauntlet" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_gauntlet);
    return module_gauntlet;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_gauntlet, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("gauntlet", false);

    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);
    return NULL;
}


/* Visibility definitions to make the DLL entry point exported */
#if defined(__GNUC__)

#if PYTHON_VERSION < 0x300

#if defined(_WIN32)
#define NUITKA_MODULE_INIT_FUNCTION __declspec(dllexport) PyMODINIT_FUNC
#else
#define NUITKA_MODULE_INIT_FUNCTION PyMODINIT_FUNC __attribute__((visibility("default")))
#endif

#else

#if defined(_WIN32)
#define NUITKA_MODULE_INIT_FUNCTION __declspec(dllexport) PyObject *
#else

#ifdef __cplusplus
#define NUITKA_MODULE_INIT_FUNCTION extern "C" __attribute__((visibility("default"))) PyObject *
#else
#define NUITKA_MODULE_INIT_FUNCTION __attribute__((visibility("default"))) PyObject *
#endif

#endif
#endif

#else
#define NUITKA_MODULE_INIT_FUNCTION PyMODINIT_FUNC
#endif

static PyObject *orig_dunder_file_value;

#if PYTHON_VERSION >= 0x300
static setattrofunc orig_PyModule_Type_tp_setattro;

/* This is used one time only. */
static int Nuitka_TopLevelModule_tp_setattro(PyObject *module, PyObject *name, PyObject *value) {
    PyModule_Type.tp_setattro = orig_PyModule_Type_tp_setattro;

    if (orig_dunder_file_value != NULL) {
        UPDATE_STRING_DICT0(
            moduledict_gauntlet,
            (Nuitka_StringObject *)const_str_plain___file__,
            orig_dunder_file_value
        );
    }

    // Prevent "__spec__" update as well.
#if PYTHON_VERSION >= 0x300
    if (PyUnicode_Check(name) && PyUnicode_Compare(name, const_str_plain___spec__) == 0) {
        return 0;
    }
#endif

    return orig_PyModule_Type_tp_setattro(module, name, value);
}
#endif

#if PYTHON_VERSION >= 0x300
static struct PyModuleDef mdef_gauntlet = {
    PyModuleDef_HEAD_INIT,
    NULL,                /* m_name, filled later */
    NULL,                /* m_doc */
    0, /* m_size */
    NULL,                /* m_methods */
    NULL,                /* m_slots */
    NULL,                /* m_traverse */
    NULL,                /* m_clear */
    NULL,                /* m_free */
};
#endif

#if PYTHON_VERSION < 0x300
static void onModuleFileValueRelease(void *v) {
    if (orig_dunder_file_value != NULL) {
        UPDATE_STRING_DICT0(
            moduledict_gauntlet,
            (Nuitka_StringObject *)const_str_plain___file__,
            orig_dunder_file_value
        );
    }
}
#endif

/* The exported interface to CPython. On import of the module, this function
 * gets called. It has to have an exact function name, in cases it's a shared
 * library export.
 */

extern struct Nuitka_MetaPathBasedLoaderEntry const *getLoaderEntry(char const *name);

static PyObject *PyInit_gauntlet_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_gauntlet(tstate, module, getLoaderEntry("gauntlet"));

#if PYTHON_VERSION < 0x300
    // Our "__file__" value will not be respected by CPython and one
    // way we can avoid it, is by having a capsule type, that when
    // it gets released, we are called and repair the value.

    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_gauntlet, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_gauntlet,
            (Nuitka_StringObject *)const_str_plain___file__,
            fake_file_value
        );
    }
#else
    if (result != NULL) {
        // Make sure we undo the change of the "__file__" attribute during importing. We do not
        // know how to achieve it for Python2 though. TODO: Find something for Python2 too.
        orig_PyModule_Type_tp_setattro = PyModule_Type.tp_setattro;
        PyModule_Type.tp_setattro = Nuitka_TopLevelModule_tp_setattro;

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_gauntlet, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_gauntlet_slot(PyObject *module) {
    PyObject *result = PyInit_gauntlet_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_gauntlet)(void) {
#if PYTHON_VERSION < 0x3c0
    if (_Py_PackageContext != NULL) {
        if (strcmp(module_full_name, _Py_PackageContext) != 0) {
            module_full_name = strdup(_Py_PackageContext);
        }
    }
#endif

#if PYTHON_VERSION < 0x300
    PyObject *module = Py_InitModule4(
        module_full_name,        // Module Name
        NULL,                    // No methods initially, all are added
                                 // dynamically in actual module code only.
        NULL,                    // No "__doc__" is initially set, as it could
                                 // not contain NUL this way, added early in
                                 // actual code.
        NULL,                    // No self for modules, we don't use it.
        PYTHON_API_VERSION
    );
#else
    mdef_gauntlet.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_gauntlet);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_gauntlet_slot},
        {0, NULL}
    };

    mdef_gauntlet.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_gauntlet);
#elif PYTHON_VERSION >= 0x300
    return PyInit_gauntlet_phase2(module);
#else
    PyInit_gauntlet_phase2(module);
#endif
}
