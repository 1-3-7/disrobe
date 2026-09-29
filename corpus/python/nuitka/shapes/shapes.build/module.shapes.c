/* Generated code for Python module 'shapes'
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



/* The "module_shapes" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_shapes;
PyDictObject *moduledict_shapes;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_str_plain_neg;
PyObject *const_str_plain_nonneg;
PyObject *const_str_chr_58;
PyObject *const_str_plain_total;
PyObject *const_str_plain_i;
PyObject *const_str_plain_apply;
PyObject *const_str_digest_53097241188096887683626243813762;
PyObject *const_str_plain_scale;
PyObject *const_str_plain_offset;
PyObject *const_tuple_type_ValueError_type_KeyError_tuple;
PyObject *const_int_neg_2;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_str_plain_join_sign;
PyObject *const_str_plain_grid_sum;
PyObject *const_str_plain_make_scaler;
PyObject *const_str_plain_lookup;
PyObject *const_int_neg_8;
PyObject *const_str_plain_neg_cube;
PyObject *const_str_plain_neg_power;
PyObject *const_str_plain_either_call;
PyObject *const_str_digest_92469c0656fa66676f977041a82f91e1;
PyObject *const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53;
PyObject *const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple;
PyObject *const_tuple_str_plain_offset_str_plain_scale_tuple;
PyObject *const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple;
PyObject *const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple;
PyObject *const_tuple_str_plain_n_str_plain_label_tuple;
PyObject *const_tuple_str_plain_table_str_plain_key_tuple;
PyObject *const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple;
PyObject *const_tuple_str_plain_n_tuple;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[31];
#endif

static PyObject *module_filename_obj = NULL;

/* Indicator if this modules private constants were created yet. */
static bool constants_created = false;

/* Function to create module private constants. */
static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("shapes"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 31) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 31 values, got %d\n",
                    UN_TRANSLATE("shapes"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_neg", mod_consts.const_str_plain_neg);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_str_plain_neg);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_nonneg", mod_consts.const_str_plain_nonneg);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_plain_nonneg);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_chr_58", mod_consts.const_str_chr_58);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_str_chr_58);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_total", mod_consts.const_str_plain_total);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_plain_total);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_i", mod_consts.const_str_plain_i);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_str_plain_i);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_apply", mod_consts.const_str_plain_apply);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_str_plain_apply);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_53097241188096887683626243813762", mod_consts.const_str_digest_53097241188096887683626243813762);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_digest_53097241188096887683626243813762);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_scale", mod_consts.const_str_plain_scale);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_str_plain_scale);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_offset", mod_consts.const_str_plain_offset);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_str_plain_offset);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_type_ValueError_type_KeyError_tuple", mod_consts.const_tuple_type_ValueError_type_KeyError_tuple);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_tuple_type_ValueError_type_KeyError_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_neg_2", mod_consts.const_int_neg_2);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_int_neg_2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_join_sign", mod_consts.const_str_plain_join_sign);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_str_plain_join_sign);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_grid_sum", mod_consts.const_str_plain_grid_sum);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_str_plain_grid_sum);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_make_scaler", mod_consts.const_str_plain_make_scaler);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_str_plain_make_scaler);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_lookup", mod_consts.const_str_plain_lookup);
mod_consts_hash[16] = DEEP_HASH(tstate, mod_consts.const_str_plain_lookup);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_neg_8", mod_consts.const_int_neg_8);
mod_consts_hash[17] = DEEP_HASH(tstate, mod_consts.const_int_neg_8);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_neg_cube", mod_consts.const_str_plain_neg_cube);
mod_consts_hash[18] = DEEP_HASH(tstate, mod_consts.const_str_plain_neg_cube);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_neg_power", mod_consts.const_str_plain_neg_power);
mod_consts_hash[19] = DEEP_HASH(tstate, mod_consts.const_str_plain_neg_power);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_either_call", mod_consts.const_str_plain_either_call);
mod_consts_hash[20] = DEEP_HASH(tstate, mod_consts.const_str_plain_either_call);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_92469c0656fa66676f977041a82f91e1", mod_consts.const_str_digest_92469c0656fa66676f977041a82f91e1);
mod_consts_hash[21] = DEEP_HASH(tstate, mod_consts.const_str_digest_92469c0656fa66676f977041a82f91e1);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53", mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53);
mod_consts_hash[22] = DEEP_HASH(tstate, mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple", mod_consts.const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple);
mod_consts_hash[23] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_offset_str_plain_scale_tuple", mod_consts.const_tuple_str_plain_offset_str_plain_scale_tuple);
mod_consts_hash[24] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_offset_str_plain_scale_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple", mod_consts.const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple);
mod_consts_hash[25] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple", mod_consts.const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple);
mod_consts_hash[26] = DEEP_HASH(tstate, mod_consts.const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_label_tuple", mod_consts.const_tuple_str_plain_n_str_plain_label_tuple);
mod_consts_hash[27] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_label_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_table_str_plain_key_tuple", mod_consts.const_tuple_str_plain_table_str_plain_key_tuple);
mod_consts_hash[28] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_table_str_plain_key_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple", mod_consts.const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple);
mod_consts_hash[29] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
mod_consts_hash[30] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple);
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
void checkModuleConstants_shapes(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_neg", mod_consts.const_str_plain_neg);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_str_plain_neg) && "mod_consts.const_str_plain_neg");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_nonneg", mod_consts.const_str_plain_nonneg);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_plain_nonneg) && "mod_consts.const_str_plain_nonneg");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_chr_58", mod_consts.const_str_chr_58);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_str_chr_58) && "mod_consts.const_str_chr_58");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_total", mod_consts.const_str_plain_total);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_plain_total) && "mod_consts.const_str_plain_total");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_i", mod_consts.const_str_plain_i);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_str_plain_i) && "mod_consts.const_str_plain_i");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_apply", mod_consts.const_str_plain_apply);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_str_plain_apply) && "mod_consts.const_str_plain_apply");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_53097241188096887683626243813762", mod_consts.const_str_digest_53097241188096887683626243813762);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_digest_53097241188096887683626243813762) && "mod_consts.const_str_digest_53097241188096887683626243813762");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_scale", mod_consts.const_str_plain_scale);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_str_plain_scale) && "mod_consts.const_str_plain_scale");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_offset", mod_consts.const_str_plain_offset);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_str_plain_offset) && "mod_consts.const_str_plain_offset");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_type_ValueError_type_KeyError_tuple", mod_consts.const_tuple_type_ValueError_type_KeyError_tuple);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_tuple_type_ValueError_type_KeyError_tuple) && "mod_consts.const_tuple_type_ValueError_type_KeyError_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_neg_2", mod_consts.const_int_neg_2);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_int_neg_2) && "mod_consts.const_int_neg_2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_join_sign", mod_consts.const_str_plain_join_sign);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_str_plain_join_sign) && "mod_consts.const_str_plain_join_sign");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_grid_sum", mod_consts.const_str_plain_grid_sum);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_str_plain_grid_sum) && "mod_consts.const_str_plain_grid_sum");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_make_scaler", mod_consts.const_str_plain_make_scaler);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_str_plain_make_scaler) && "mod_consts.const_str_plain_make_scaler");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_lookup", mod_consts.const_str_plain_lookup);
assert(mod_consts_hash[16] == DEEP_HASH(tstate, mod_consts.const_str_plain_lookup) && "mod_consts.const_str_plain_lookup");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_neg_8", mod_consts.const_int_neg_8);
assert(mod_consts_hash[17] == DEEP_HASH(tstate, mod_consts.const_int_neg_8) && "mod_consts.const_int_neg_8");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_neg_cube", mod_consts.const_str_plain_neg_cube);
assert(mod_consts_hash[18] == DEEP_HASH(tstate, mod_consts.const_str_plain_neg_cube) && "mod_consts.const_str_plain_neg_cube");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_neg_power", mod_consts.const_str_plain_neg_power);
assert(mod_consts_hash[19] == DEEP_HASH(tstate, mod_consts.const_str_plain_neg_power) && "mod_consts.const_str_plain_neg_power");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_either_call", mod_consts.const_str_plain_either_call);
assert(mod_consts_hash[20] == DEEP_HASH(tstate, mod_consts.const_str_plain_either_call) && "mod_consts.const_str_plain_either_call");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_92469c0656fa66676f977041a82f91e1", mod_consts.const_str_digest_92469c0656fa66676f977041a82f91e1);
assert(mod_consts_hash[21] == DEEP_HASH(tstate, mod_consts.const_str_digest_92469c0656fa66676f977041a82f91e1) && "mod_consts.const_str_digest_92469c0656fa66676f977041a82f91e1");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53", mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53);
assert(mod_consts_hash[22] == DEEP_HASH(tstate, mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53) && "mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple", mod_consts.const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple);
assert(mod_consts_hash[23] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple) && "mod_consts.const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_offset_str_plain_scale_tuple", mod_consts.const_tuple_str_plain_offset_str_plain_scale_tuple);
assert(mod_consts_hash[24] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_offset_str_plain_scale_tuple) && "mod_consts.const_tuple_str_plain_offset_str_plain_scale_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple", mod_consts.const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple);
assert(mod_consts_hash[25] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple) && "mod_consts.const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple", mod_consts.const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple);
assert(mod_consts_hash[26] == DEEP_HASH(tstate, mod_consts.const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple) && "mod_consts.const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_label_tuple", mod_consts.const_tuple_str_plain_n_str_plain_label_tuple);
assert(mod_consts_hash[27] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_label_tuple) && "mod_consts.const_tuple_str_plain_n_str_plain_label_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_table_str_plain_key_tuple", mod_consts.const_tuple_str_plain_table_str_plain_key_tuple);
assert(mod_consts_hash[28] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_table_str_plain_key_tuple) && "mod_consts.const_tuple_str_plain_table_str_plain_key_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple", mod_consts.const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple);
assert(mod_consts_hash[29] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple) && "mod_consts.const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
assert(mod_consts_hash[30] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple) && "mod_consts.const_tuple_str_plain_n_tuple");
}
#endif

// Helper to preserving module variables for Python3.11+
#if 1
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
static PyObject *module_var_accessor_shapes$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_shapes->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_shapes->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_shapes->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_3dca97c3e5c2752a0fecbbc3fcb7889f;
static PyCodeObject *code_objects_f99e1f1823ca7c9f25ec33a4ab92bdcc;
static PyCodeObject *code_objects_6c812891b8b3582bf6f1c664131d1e57;
static PyCodeObject *code_objects_f4b67b542c978c1d0562935e8e6c8ec6;
static PyCodeObject *code_objects_c323ed51460a9c13426b5b942b8b358b;
static PyCodeObject *code_objects_aeb9a176346527b9bcc90adfb8a01489;
static PyCodeObject *code_objects_bfecf7c8a2840d69b3df1bd89d7d3c3d;
static PyCodeObject *code_objects_311b708662e47f288093f69621234a91;
static PyCodeObject *code_objects_6439fad1d7f389be702e61febb91e453;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_92469c0656fa66676f977041a82f91e1); CHECK_OBJECT(module_filename_obj);
code_objects_3dca97c3e5c2752a0fecbbc3fcb7889f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53, mod_consts.const_str_digest_fbc3104bbe0cdcf81a0c2be15b212e53, NULL, NULL, 0, 0, 0);
code_objects_f99e1f1823ca7c9f25ec33a4ab92bdcc = MAKE_CODE_OBJECT(module_filename_obj, 18, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_apply, mod_consts.const_str_digest_53097241188096887683626243813762, mod_consts.const_tuple_str_plain_x_str_plain_scale_str_plain_offset_tuple, mod_consts.const_tuple_str_plain_offset_str_plain_scale_tuple, 1, 0, 0);
code_objects_6c812891b8b3582bf6f1c664131d1e57 = MAKE_CODE_OBJECT(module_filename_obj, 39, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_either_call, mod_consts.const_str_plain_either_call, mod_consts.const_tuple_str_plain_f_str_plain_g_str_plain_x_tuple, NULL, 3, 0, 0);
code_objects_f4b67b542c978c1d0562935e8e6c8ec6 = MAKE_CODE_OBJECT(module_filename_obj, 9, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_grid_sum, mod_consts.const_str_plain_grid_sum, mod_consts.const_tuple_12ec366fe6957fcedb51bd14108c9f0c_tuple, NULL, 2, 0, 0);
code_objects_c323ed51460a9c13426b5b942b8b358b = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_join_sign, mod_consts.const_str_plain_join_sign, mod_consts.const_tuple_str_plain_n_str_plain_label_tuple, NULL, 1, 0, 0);
code_objects_aeb9a176346527b9bcc90adfb8a01489 = MAKE_CODE_OBJECT(module_filename_obj, 24, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_lookup, mod_consts.const_str_plain_lookup, mod_consts.const_tuple_str_plain_table_str_plain_key_tuple, NULL, 2, 0, 0);
code_objects_bfecf7c8a2840d69b3df1bd89d7d3c3d = MAKE_CODE_OBJECT(module_filename_obj, 17, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_make_scaler, mod_consts.const_str_plain_make_scaler, mod_consts.const_tuple_str_plain_scale_str_plain_offset_str_plain_apply_tuple, NULL, 2, 0, 0);
code_objects_311b708662e47f288093f69621234a91 = MAKE_CODE_OBJECT(module_filename_obj, 31, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_neg_cube, mod_consts.const_str_plain_neg_cube, NULL, NULL, 0, 0, 0);
code_objects_6439fad1d7f389be702e61febb91e453 = MAKE_CODE_OBJECT(module_filename_obj, 35, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_neg_power, mod_consts.const_str_plain_neg_power, mod_consts.const_tuple_str_plain_n_tuple, NULL, 1, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION_shapes$$$function__1_join_sign(PyThreadState *tstate);


static PyObject *MAKE_FUNCTION_shapes$$$function__2_grid_sum(PyThreadState *tstate);


static PyObject *MAKE_FUNCTION_shapes$$$function__3_make_scaler(PyThreadState *tstate);


static PyObject *MAKE_FUNCTION_shapes$$$function__3_make_scaler$$$function__1_apply(PyThreadState *tstate, struct Nuitka_CellObject **closure);


static PyObject *MAKE_FUNCTION_shapes$$$function__4_lookup(PyThreadState *tstate);


static PyObject *MAKE_FUNCTION_shapes$$$function__5_neg_cube(PyThreadState *tstate);


static PyObject *MAKE_FUNCTION_shapes$$$function__6_neg_power(PyThreadState *tstate);


static PyObject *MAKE_FUNCTION_shapes$$$function__7_either_call(PyThreadState *tstate);


// The module function definitions.
static PyObject *impl_shapes$$$function__1_join_sign(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_n = python_pars[0];
PyObject *var_label = NULL;
struct Nuitka_FrameObject *frame_frame_shapes$$$function__1_join_sign;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
PyObject *tmp_return_value = NULL;
static struct Nuitka_FrameObject *cache_frame_frame_shapes$$$function__1_join_sign = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;

    // Actual function body.
// Tried code:
if (isFrameUnusable(cache_frame_frame_shapes$$$function__1_join_sign)) {
    Py_XDECREF(cache_frame_frame_shapes$$$function__1_join_sign);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_shapes$$$function__1_join_sign == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_shapes$$$function__1_join_sign = MAKE_FUNCTION_FRAME(tstate, code_objects_c323ed51460a9c13426b5b942b8b358b, module_shapes, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_shapes$$$function__1_join_sign->m_type_description == NULL);
frame_frame_shapes$$$function__1_join_sign = cache_frame_frame_shapes$$$function__1_join_sign;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_shapes$$$function__1_join_sign);
assert(Py_REFCNT(frame_frame_shapes$$$function__1_join_sign) == 2);

// Framed code:
{
nuitka_bool tmp_condition_result_1;
PyObject *tmp_cmp_expr_left_1;
PyObject *tmp_cmp_expr_right_1;
CHECK_OBJECT(par_n);
tmp_cmp_expr_left_1 = par_n;
tmp_cmp_expr_right_1 = const_int_0;
tmp_condition_result_1 = RICH_COMPARE_LT_NBOOL_OBJECT_LONG(tmp_cmp_expr_left_1, tmp_cmp_expr_right_1);
if (tmp_condition_result_1 == NUITKA_BOOL_EXCEPTION) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "oo";
    goto frame_exception_exit_1;
}
if (tmp_condition_result_1 == NUITKA_BOOL_TRUE) {
    goto branch_yes_1;
} else {
    goto branch_no_1;
}
}
branch_yes_1:;
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = mod_consts.const_str_plain_neg;
{
    PyObject *old = var_label;
    var_label = tmp_assign_source_1;
    Py_INCREF(var_label);
    Py_XDECREF(old);
}

}
goto branch_end_1;
branch_no_1:;
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = mod_consts.const_str_plain_nonneg;
{
    PyObject *old = var_label;
    var_label = tmp_assign_source_2;
    Py_INCREF(var_label);
    Py_XDECREF(old);
}

}
branch_end_1:;
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
PyObject *tmp_add_expr_left_2;
PyObject *tmp_add_expr_right_2;
PyObject *tmp_unicode_arg_1;
CHECK_OBJECT(var_label);
tmp_add_expr_left_2 = var_label;
tmp_add_expr_right_2 = mod_consts.const_str_chr_58;
tmp_add_expr_left_1 = BINARY_OPERATION_ADD_OBJECT_UNICODE_UNICODE(tmp_add_expr_left_2, tmp_add_expr_right_2);
assert(!(tmp_add_expr_left_1 == NULL));
CHECK_OBJECT(par_n);
tmp_unicode_arg_1 = par_n;
tmp_add_expr_right_1 = BUILTIN_UNICODE1(tmp_unicode_arg_1);
if (tmp_add_expr_right_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
Py_DECREF(tmp_add_expr_left_1);

exception_lineno = 6;
type_description_1 = "oo";
    goto frame_exception_exit_1;
}
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_UNICODE_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
CHECK_OBJECT(tmp_add_expr_left_1);
Py_DECREF(tmp_add_expr_left_1);
CHECK_OBJECT(tmp_add_expr_right_1);
Py_DECREF(tmp_add_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 6;
type_description_1 = "oo";
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
        exception_tb = MAKE_TRACEBACK(frame_frame_shapes$$$function__1_join_sign, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_shapes$$$function__1_join_sign->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_shapes$$$function__1_join_sign, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_shapes$$$function__1_join_sign,
    type_description_1,
    par_n,
    var_label
);


// Release cached frame if used for exception.
if (frame_frame_shapes$$$function__1_join_sign == cache_frame_frame_shapes$$$function__1_join_sign) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_shapes$$$function__1_join_sign);
    cache_frame_frame_shapes$$$function__1_join_sign = NULL;
}

assertFrameObject(frame_frame_shapes$$$function__1_join_sign);

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
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_label);
var_label = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

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


static PyObject *impl_shapes$$$function__2_grid_sum(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_rows = python_pars[0];
PyObject *par_cols = python_pars[1];
PyObject *var_total = NULL;
PyObject *var_i = NULL;
PyObject *var_j = NULL;
PyObject *tmp_for_loop_1__for_iterator = NULL;
PyObject *tmp_for_loop_1__iter_value = NULL;
PyObject *tmp_for_loop_2__for_iterator = NULL;
PyObject *tmp_for_loop_2__iter_value = NULL;
struct Nuitka_FrameObject *frame_frame_shapes$$$function__2_grid_sum;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
PyObject *tmp_return_value = NULL;
static struct Nuitka_FrameObject *cache_frame_frame_shapes$$$function__2_grid_sum = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_3;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_3;

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
if (isFrameUnusable(cache_frame_frame_shapes$$$function__2_grid_sum)) {
    Py_XDECREF(cache_frame_frame_shapes$$$function__2_grid_sum);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_shapes$$$function__2_grid_sum == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_shapes$$$function__2_grid_sum = MAKE_FUNCTION_FRAME(tstate, code_objects_f4b67b542c978c1d0562935e8e6c8ec6, module_shapes, sizeof(void *)+sizeof(void *)+sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_shapes$$$function__2_grid_sum->m_type_description == NULL);
frame_frame_shapes$$$function__2_grid_sum = cache_frame_frame_shapes$$$function__2_grid_sum;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_shapes$$$function__2_grid_sum);
assert(Py_REFCNT(frame_frame_shapes$$$function__2_grid_sum) == 2);

// Framed code:
{
PyObject *tmp_assign_source_2;
PyObject *tmp_iter_arg_1;
PyObject *tmp_xrange_low_1;
CHECK_OBJECT(par_rows);
tmp_xrange_low_1 = par_rows;
tmp_iter_arg_1 = BUILTIN_XRANGE1(tstate, tmp_xrange_low_1);
if (tmp_iter_arg_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 11;
type_description_1 = "ooooo";
    goto frame_exception_exit_1;
}
tmp_assign_source_2 = MAKE_ITERATOR(tstate, tmp_iter_arg_1);
CHECK_OBJECT(tmp_iter_arg_1);
Py_DECREF(tmp_iter_arg_1);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 11;
type_description_1 = "ooooo";
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
tmp_assign_source_3 = ITERATOR_NEXT_ITERATOR(tmp_next_source_1);
if (tmp_assign_source_3 == NULL) {
    if (CHECK_AND_CLEAR_STOP_ITERATION_OCCURRED(tstate)) {

        goto loop_end_1;
    } else {

        FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
type_description_1 = "ooooo";
exception_lineno = 11;
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
    PyObject *old = var_i;
    var_i = tmp_assign_source_4;
    Py_INCREF(var_i);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_iter_arg_2;
PyObject *tmp_xrange_low_2;
CHECK_OBJECT(par_cols);
tmp_xrange_low_2 = par_cols;
tmp_iter_arg_2 = BUILTIN_XRANGE1(tstate, tmp_xrange_low_2);
if (tmp_iter_arg_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 12;
type_description_1 = "ooooo";
    goto try_except_handler_2;
}
tmp_assign_source_5 = MAKE_ITERATOR(tstate, tmp_iter_arg_2);
CHECK_OBJECT(tmp_iter_arg_2);
Py_DECREF(tmp_iter_arg_2);
if (tmp_assign_source_5 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 12;
type_description_1 = "ooooo";
    goto try_except_handler_2;
}
{
    PyObject *old = tmp_for_loop_2__for_iterator;
    tmp_for_loop_2__for_iterator = tmp_assign_source_5;
    Py_XDECREF(old);
}

}
// Tried code:
loop_start_2:;
{
PyObject *tmp_next_source_2;
PyObject *tmp_assign_source_6;
CHECK_OBJECT(tmp_for_loop_2__for_iterator);
tmp_next_source_2 = tmp_for_loop_2__for_iterator;
tmp_assign_source_6 = ITERATOR_NEXT_ITERATOR(tmp_next_source_2);
if (tmp_assign_source_6 == NULL) {
    if (CHECK_AND_CLEAR_STOP_ITERATION_OCCURRED(tstate)) {

        goto loop_end_2;
    } else {

        FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
type_description_1 = "ooooo";
exception_lineno = 12;
        goto try_except_handler_3;
    }
}

{
    PyObject *old = tmp_for_loop_2__iter_value;
    tmp_for_loop_2__iter_value = tmp_assign_source_6;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_7;
CHECK_OBJECT(tmp_for_loop_2__iter_value);
tmp_assign_source_7 = tmp_for_loop_2__iter_value;
{
    PyObject *old = var_j;
    var_j = tmp_assign_source_7;
    Py_INCREF(var_j);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
PyObject *tmp_mult_expr_left_1;
PyObject *tmp_mult_expr_right_1;
if (var_total == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_total);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 13;
type_description_1 = "ooooo";
    goto try_except_handler_3;
}

tmp_add_expr_left_1 = var_total;
if (var_i == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_i);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 13;
type_description_1 = "ooooo";
    goto try_except_handler_3;
}

tmp_mult_expr_left_1 = var_i;
CHECK_OBJECT(var_j);
tmp_mult_expr_right_1 = var_j;
tmp_add_expr_right_1 = BINARY_OPERATION_MULT_OBJECT_OBJECT_OBJECT(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
if (tmp_add_expr_right_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 13;
type_description_1 = "ooooo";
    goto try_except_handler_3;
}
tmp_assign_source_8 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
CHECK_OBJECT(tmp_add_expr_right_1);
Py_DECREF(tmp_add_expr_right_1);
if (tmp_assign_source_8 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 13;
type_description_1 = "ooooo";
    goto try_except_handler_3;
}
{
    PyObject *old = var_total;
    var_total = tmp_assign_source_8;
    Py_XDECREF(old);
}

}
if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 12;
type_description_1 = "ooooo";
    goto try_except_handler_3;
}
goto loop_start_2;
loop_end_2:;
goto try_end_1;
// Exception handler code:
try_except_handler_3:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_for_loop_2__iter_value);
tmp_for_loop_2__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_2__for_iterator);
CHECK_OBJECT(tmp_for_loop_2__for_iterator);
Py_DECREF(tmp_for_loop_2__for_iterator);
tmp_for_loop_2__for_iterator = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto try_except_handler_2;
// End of try:
try_end_1:;
Py_XDECREF(tmp_for_loop_2__iter_value);
tmp_for_loop_2__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_2__for_iterator);
CHECK_OBJECT(tmp_for_loop_2__for_iterator);
Py_DECREF(tmp_for_loop_2__for_iterator);
tmp_for_loop_2__for_iterator = NULL;
if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 11;
type_description_1 = "ooooo";
    goto try_except_handler_2;
}
goto loop_start_1;
loop_end_1:;
goto try_end_2;
// Exception handler code:
try_except_handler_2:;
exception_keeper_lineno_2 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_2 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_for_loop_1__iter_value);
tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
Py_DECREF(tmp_for_loop_1__for_iterator);
tmp_for_loop_1__for_iterator = NULL;
// Re-raise.
exception_state = exception_keeper_name_2;
exception_lineno = exception_keeper_lineno_2;

goto frame_exception_exit_1;
// End of try:
try_end_2:;
Py_XDECREF(tmp_for_loop_1__iter_value);
tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
Py_DECREF(tmp_for_loop_1__for_iterator);
tmp_for_loop_1__for_iterator = NULL;
if (var_total == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_total);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 14;
type_description_1 = "ooooo";
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
        exception_tb = MAKE_TRACEBACK(frame_frame_shapes$$$function__2_grid_sum, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_shapes$$$function__2_grid_sum->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_shapes$$$function__2_grid_sum, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_shapes$$$function__2_grid_sum,
    type_description_1,
    par_rows,
    par_cols,
    var_total,
    var_i,
    var_j
);


// Release cached frame if used for exception.
if (frame_frame_shapes$$$function__2_grid_sum == cache_frame_frame_shapes$$$function__2_grid_sum) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_shapes$$$function__2_grid_sum);
    cache_frame_frame_shapes$$$function__2_grid_sum = NULL;
}

assertFrameObject(frame_frame_shapes$$$function__2_grid_sum);

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
Py_XDECREF(var_i);
var_i = NULL;
Py_XDECREF(var_j);
var_j = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_3 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_3 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_total);
var_total = NULL;
Py_XDECREF(var_i);
var_i = NULL;
Py_XDECREF(var_j);
var_j = NULL;
// Re-raise.
exception_state = exception_keeper_name_3;
exception_lineno = exception_keeper_lineno_3;

goto function_exception_exit;
// End of try:

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_rows);
Py_DECREF(par_rows);
CHECK_OBJECT(par_cols);
Py_DECREF(par_cols);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_rows);
Py_DECREF(par_rows);
CHECK_OBJECT(par_cols);
Py_DECREF(par_cols);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_shapes$$$function__3_make_scaler(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
struct Nuitka_CellObject *par_scale = Nuitka_Cell_New1(python_pars[0]);
struct Nuitka_CellObject *par_offset = Nuitka_Cell_New1(python_pars[1]);
PyObject *var_apply = NULL;
PyObject *tmp_return_value = NULL;

    // Actual function body.
{
PyObject *tmp_assign_source_1;
struct Nuitka_CellObject *tmp_closure_1[2];
tmp_closure_1[0] = par_offset;
Py_INCREF(tmp_closure_1[0]);
tmp_closure_1[1] = par_scale;
Py_INCREF(tmp_closure_1[1]);
tmp_assign_source_1 = MAKE_FUNCTION_shapes$$$function__3_make_scaler$$$function__1_apply(tstate, tmp_closure_1);

{
    PyObject *old = var_apply;
    var_apply = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
// Tried code:
CHECK_OBJECT(var_apply);
tmp_return_value = var_apply;
Py_INCREF(tmp_return_value);
goto try_return_handler_1;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
CHECK_OBJECT(par_scale);
CHECK_OBJECT(par_scale);
Py_DECREF(par_scale);
par_scale = NULL;
CHECK_OBJECT(par_offset);
CHECK_OBJECT(par_offset);
Py_DECREF(par_offset);
par_offset = NULL;
CHECK_OBJECT(var_apply);
CHECK_OBJECT(var_apply);
Py_DECREF(var_apply);
var_apply = NULL;
goto function_return_exit;
// End of try:

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;


function_return_exit:
   // Function cleanup code if any.


   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_shapes$$$function__3_make_scaler$$$function__1_apply(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_x = python_pars[0];
struct Nuitka_FrameObject *frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply)) {
    Py_XDECREF(cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply = MAKE_FUNCTION_FRAME(tstate, code_objects_f99e1f1823ca7c9f25ec33a4ab92bdcc, module_shapes, sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply->m_type_description == NULL);
frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply = cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply);
assert(Py_REFCNT(frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply) == 2);

// Framed code:
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
PyObject *tmp_mult_expr_left_1;
PyObject *tmp_mult_expr_right_1;
CHECK_OBJECT(par_x);
tmp_mult_expr_left_1 = par_x;
if (Nuitka_Cell_GET(self->m_closure[1]) == NULL) {

FORMAT_UNBOUND_CLOSURE_ERROR(tstate, &exception_state, mod_consts.const_str_plain_scale);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 19;
type_description_1 = "occ";
    goto frame_exception_exit_1;
}

tmp_mult_expr_right_1 = Nuitka_Cell_GET(self->m_closure[1]);
tmp_add_expr_left_1 = BINARY_OPERATION_MULT_OBJECT_OBJECT_OBJECT(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
if (tmp_add_expr_left_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 19;
type_description_1 = "occ";
    goto frame_exception_exit_1;
}
if (Nuitka_Cell_GET(self->m_closure[0]) == NULL) {
Py_DECREF(tmp_add_expr_left_1);
FORMAT_UNBOUND_CLOSURE_ERROR(tstate, &exception_state, mod_consts.const_str_plain_offset);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 19;
type_description_1 = "occ";
    goto frame_exception_exit_1;
}

tmp_add_expr_right_1 = Nuitka_Cell_GET(self->m_closure[0]);
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
CHECK_OBJECT(tmp_add_expr_left_1);
Py_DECREF(tmp_add_expr_left_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 19;
type_description_1 = "occ";
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
        exception_tb = MAKE_TRACEBACK(frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply,
    type_description_1,
    par_x,
    self->m_closure[1],
    self->m_closure[0]
);


// Release cached frame if used for exception.
if (frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply == cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply);
    cache_frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply = NULL;
}

assertFrameObject(frame_frame_shapes$$$function__3_make_scaler$$$function__1_apply);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_x);
Py_DECREF(par_x);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_x);
Py_DECREF(par_x);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_shapes$$$function__4_lookup(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_table = python_pars[0];
PyObject *par_key = python_pars[1];
struct Nuitka_FrameObject *frame_frame_shapes$$$function__4_lookup;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionStackItem exception_preserved_1;
int tmp_res;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
static struct Nuitka_FrameObject *cache_frame_frame_shapes$$$function__4_lookup = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_shapes$$$function__4_lookup)) {
    Py_XDECREF(cache_frame_frame_shapes$$$function__4_lookup);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_shapes$$$function__4_lookup == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_shapes$$$function__4_lookup = MAKE_FUNCTION_FRAME(tstate, code_objects_aeb9a176346527b9bcc90adfb8a01489, module_shapes, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_shapes$$$function__4_lookup->m_type_description == NULL);
frame_frame_shapes$$$function__4_lookup = cache_frame_frame_shapes$$$function__4_lookup;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_shapes$$$function__4_lookup);
assert(Py_REFCNT(frame_frame_shapes$$$function__4_lookup) == 2);

// Framed code:
// Tried code:
{
PyObject *tmp_int_arg_1;
PyObject *tmp_expression_value_1;
PyObject *tmp_subscript_value_1;
CHECK_OBJECT(par_table);
tmp_expression_value_1 = par_table;
CHECK_OBJECT(par_key);
tmp_subscript_value_1 = par_key;
tmp_int_arg_1 = LOOKUP_SUBSCRIPT(tstate, tmp_expression_value_1, tmp_subscript_value_1);
if (tmp_int_arg_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 26;
type_description_1 = "oo";
    goto try_except_handler_1;
}
tmp_return_value = PyNumber_Int(tmp_int_arg_1);
CHECK_OBJECT(tmp_int_arg_1);
Py_DECREF(tmp_int_arg_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 26;
type_description_1 = "oo";
    goto try_except_handler_1;
}
goto frame_return_exit_1;
}
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

// Preserve existing published exception id 1.
exception_preserved_1 = GET_CURRENT_EXCEPTION(tstate);

{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_keeper_name_1);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_shapes$$$function__4_lookup, exception_keeper_lineno_1);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_keeper_name_1, exception_tb);
    } else if (exception_keeper_lineno_1 != 0) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_shapes$$$function__4_lookup, exception_keeper_lineno_1);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_keeper_name_1, exception_tb);
    }
}

PUBLISH_CURRENT_EXCEPTION(tstate, &exception_keeper_name_1);
// Tried code:
{
bool tmp_condition_result_1;
PyObject *tmp_cmp_expr_left_1;
PyObject *tmp_cmp_expr_right_1;
tmp_cmp_expr_left_1 = EXC_TYPE(tstate);
tmp_cmp_expr_right_1 = mod_consts.const_tuple_type_ValueError_type_KeyError_tuple;
tmp_res = EXCEPTION_MATCH_BOOL(tstate, tmp_cmp_expr_left_1, tmp_cmp_expr_right_1);
if (tmp_res == -1) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 27;
type_description_1 = "oo";
    goto try_except_handler_2;
}
tmp_condition_result_1 = (tmp_res != 0) ? true : false;
if (tmp_condition_result_1 != false) {
    goto branch_yes_1;
} else {
    goto branch_no_1;
}
}
branch_yes_1:;
tmp_return_value = const_int_neg_1;
Py_INCREF(tmp_return_value);
goto try_return_handler_2;
goto branch_end_1;
branch_no_1:;
tmp_result = RERAISE_EXCEPTION(tstate, &exception_state);
if (unlikely(tmp_result == false)) {
    exception_lineno = 25;
}

{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);

    if ((exception_tb != NULL) && (exception_tb->tb_frame == &frame_frame_shapes$$$function__4_lookup->m_frame)) {
        frame_frame_shapes$$$function__4_lookup->m_frame.f_lineno = exception_tb->tb_lineno;
    }
}
type_description_1 = "oo";
goto try_except_handler_2;
branch_end_1:;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_2:;
// Restore previous exception id 1.
SET_CURRENT_EXCEPTION(tstate, &exception_preserved_1);

goto frame_return_exit_1;
// Exception handler code:
try_except_handler_2:;
exception_keeper_lineno_2 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_2 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

// Restore previous exception id 1.
SET_CURRENT_EXCEPTION(tstate, &exception_preserved_1);

// Re-raise.
exception_state = exception_keeper_name_2;
exception_lineno = exception_keeper_lineno_2;

goto frame_exception_exit_1;
// End of try:
// End of try:


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
        exception_tb = MAKE_TRACEBACK(frame_frame_shapes$$$function__4_lookup, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_shapes$$$function__4_lookup->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_shapes$$$function__4_lookup, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_shapes$$$function__4_lookup,
    type_description_1,
    par_table,
    par_key
);


// Release cached frame if used for exception.
if (frame_frame_shapes$$$function__4_lookup == cache_frame_frame_shapes$$$function__4_lookup) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_shapes$$$function__4_lookup);
    cache_frame_frame_shapes$$$function__4_lookup = NULL;
}

assertFrameObject(frame_frame_shapes$$$function__4_lookup);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_table);
Py_DECREF(par_table);
CHECK_OBJECT(par_key);
Py_DECREF(par_key);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_table);
Py_DECREF(par_table);
CHECK_OBJECT(par_key);
Py_DECREF(par_key);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_shapes$$$function__6_neg_power(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_n = python_pars[0];
struct Nuitka_FrameObject *frame_frame_shapes$$$function__6_neg_power;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_shapes$$$function__6_neg_power = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_shapes$$$function__6_neg_power)) {
    Py_XDECREF(cache_frame_frame_shapes$$$function__6_neg_power);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_shapes$$$function__6_neg_power == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_shapes$$$function__6_neg_power = MAKE_FUNCTION_FRAME(tstate, code_objects_6439fad1d7f389be702e61febb91e453, module_shapes, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_shapes$$$function__6_neg_power->m_type_description == NULL);
frame_frame_shapes$$$function__6_neg_power = cache_frame_frame_shapes$$$function__6_neg_power;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_shapes$$$function__6_neg_power);
assert(Py_REFCNT(frame_frame_shapes$$$function__6_neg_power) == 2);

// Framed code:
{
PyObject *tmp_pow_expr_left_1;
PyObject *tmp_pow_expr_right_1;
tmp_pow_expr_left_1 = mod_consts.const_int_neg_2;
CHECK_OBJECT(par_n);
tmp_pow_expr_right_1 = par_n;
tmp_return_value = BINARY_OPERATION_POW_OBJECT_LONG_OBJECT(tmp_pow_expr_left_1, tmp_pow_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 36;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_shapes$$$function__6_neg_power, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_shapes$$$function__6_neg_power->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_shapes$$$function__6_neg_power, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_shapes$$$function__6_neg_power,
    type_description_1,
    par_n
);


// Release cached frame if used for exception.
if (frame_frame_shapes$$$function__6_neg_power == cache_frame_frame_shapes$$$function__6_neg_power) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_shapes$$$function__6_neg_power);
    cache_frame_frame_shapes$$$function__6_neg_power = NULL;
}

assertFrameObject(frame_frame_shapes$$$function__6_neg_power);

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


static PyObject *impl_shapes$$$function__7_either_call(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_f = python_pars[0];
PyObject *par_g = python_pars[1];
PyObject *par_x = python_pars[2];
struct Nuitka_FrameObject *frame_frame_shapes$$$function__7_either_call;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_shapes$$$function__7_either_call = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_shapes$$$function__7_either_call)) {
    Py_XDECREF(cache_frame_frame_shapes$$$function__7_either_call);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_shapes$$$function__7_either_call == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_shapes$$$function__7_either_call = MAKE_FUNCTION_FRAME(tstate, code_objects_6c812891b8b3582bf6f1c664131d1e57, module_shapes, sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_shapes$$$function__7_either_call->m_type_description == NULL);
frame_frame_shapes$$$function__7_either_call = cache_frame_frame_shapes$$$function__7_either_call;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_shapes$$$function__7_either_call);
assert(Py_REFCNT(frame_frame_shapes$$$function__7_either_call) == 2);

// Framed code:
{
PyObject *tmp_called_value_1;
int tmp_or_left_truth_1;
PyObject *tmp_or_left_value_1;
PyObject *tmp_or_right_value_1;
PyObject *tmp_args_element_value_1;
CHECK_OBJECT(par_f);
tmp_or_left_value_1 = par_f;
tmp_or_left_truth_1 = CHECK_IF_TRUE(tmp_or_left_value_1);
if (tmp_or_left_truth_1 == -1) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 40;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
if (tmp_or_left_truth_1 == 1) {
    goto or_left_1;
} else {
    goto or_right_1;
}
or_right_1:;
CHECK_OBJECT(par_g);
tmp_or_right_value_1 = par_g;
tmp_called_value_1 = tmp_or_right_value_1;
goto or_end_1;
or_left_1:;
tmp_called_value_1 = tmp_or_left_value_1;
or_end_1:;
CHECK_OBJECT(par_x);
tmp_args_element_value_1 = par_x;
frame_frame_shapes$$$function__7_either_call->m_frame.f_lineno = 40;
tmp_return_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_1, tmp_args_element_value_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 40;
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

goto function_return_exit;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_shapes$$$function__7_either_call, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_shapes$$$function__7_either_call->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_shapes$$$function__7_either_call, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_shapes$$$function__7_either_call,
    type_description_1,
    par_f,
    par_g,
    par_x
);


// Release cached frame if used for exception.
if (frame_frame_shapes$$$function__7_either_call == cache_frame_frame_shapes$$$function__7_either_call) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_shapes$$$function__7_either_call);
    cache_frame_frame_shapes$$$function__7_either_call = NULL;
}

assertFrameObject(frame_frame_shapes$$$function__7_either_call);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_f);
Py_DECREF(par_f);
CHECK_OBJECT(par_g);
Py_DECREF(par_g);
CHECK_OBJECT(par_x);
Py_DECREF(par_x);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_f);
Py_DECREF(par_f);
CHECK_OBJECT(par_g);
Py_DECREF(par_g);
CHECK_OBJECT(par_x);
Py_DECREF(par_x);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}



static PyObject *MAKE_FUNCTION_shapes$$$function__1_join_sign(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_shapes$$$function__1_join_sign,
        mod_consts.const_str_plain_join_sign,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_c323ed51460a9c13426b5b942b8b358b,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_shapes,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_shapes$$$function__2_grid_sum(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_shapes$$$function__2_grid_sum,
        mod_consts.const_str_plain_grid_sum,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_f4b67b542c978c1d0562935e8e6c8ec6,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_shapes,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_shapes$$$function__3_make_scaler(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_shapes$$$function__3_make_scaler,
        mod_consts.const_str_plain_make_scaler,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_bfecf7c8a2840d69b3df1bd89d7d3c3d,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_shapes,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_shapes$$$function__3_make_scaler$$$function__1_apply(PyThreadState *tstate, struct Nuitka_CellObject **closure) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_shapes$$$function__3_make_scaler$$$function__1_apply,
        mod_consts.const_str_plain_apply,
#if PYTHON_VERSION >= 0x300
        mod_consts.const_str_digest_53097241188096887683626243813762,
#endif
        code_objects_f99e1f1823ca7c9f25ec33a4ab92bdcc,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_shapes,
        NULL,
        closure,
        2
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_shapes$$$function__4_lookup(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_shapes$$$function__4_lookup,
        mod_consts.const_str_plain_lookup,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_aeb9a176346527b9bcc90adfb8a01489,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_shapes,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_shapes$$$function__5_neg_cube(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        NULL,
        mod_consts.const_str_plain_neg_cube,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_311b708662e47f288093f69621234a91,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_shapes,
        NULL,
        NULL,
        0
    );
Nuitka_Function_EnableConstReturnGeneric(result, mod_consts.const_int_neg_8);

    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_shapes$$$function__6_neg_power(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_shapes$$$function__6_neg_power,
        mod_consts.const_str_plain_neg_power,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_6439fad1d7f389be702e61febb91e453,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_shapes,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_shapes$$$function__7_either_call(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_shapes$$$function__7_either_call,
        mod_consts.const_str_plain_either_call,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_6c812891b8b3582bf6f1c664131d1e57,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_shapes,
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

static function_impl_code const function_table_shapes[] = {
impl_shapes$$$function__3_make_scaler$$$function__1_apply,
impl_shapes$$$function__1_join_sign,
impl_shapes$$$function__2_grid_sum,
impl_shapes$$$function__3_make_scaler,
impl_shapes$$$function__4_lookup,
impl_shapes$$$function__6_neg_power,
impl_shapes$$$function__7_either_call,
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

    return Nuitka_Function_GetFunctionState(function, function_table_shapes);
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
        module_shapes,
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
        function_table_shapes,
        sizeof(function_table_shapes) / sizeof(function_impl_code)
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
static char const *module_full_name = "shapes";
#endif

// Internal entry point for module code.
PyObject *module_code_shapes(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("shapes");

    // Store the module for future use.
    module_shapes = module;

    moduledict_shapes = MODULE_DICT(module_shapes);

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
        PRINT_STRING("shapes: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("shapes: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("shapes: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "shapes" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initshapes\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict_shapes,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_shapes,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_shapes,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_shapes,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_shapes,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_shapes);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_shapes);
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

        UPDATE_STRING_DICT1(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_shapes;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_shapes = MAKE_MODULE_FRAME(code_objects_3dca97c3e5c2752a0fecbbc3fcb7889f, module_shapes);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_shapes);
assert(Py_REFCNT(frame_frame_shapes) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_shapes$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_shapes$__spec__(tstate);
assert(!(tmp_ass_attr_target_2 == NULL));
tmp_result = SET_ATTRIBUTE(tstate, tmp_ass_attr_target_2, mod_consts.const_str_plain_has_location, tmp_ass_attr_value_2);
if (tmp_result == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

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
        exception_tb = MAKE_TRACEBACK(frame_frame_shapes, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_shapes->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_shapes, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_shapes);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;

tmp_assign_source_5 = MAKE_FUNCTION_shapes$$$function__1_join_sign(tstate);

UPDATE_STRING_DICT1(moduledict_shapes, (Nuitka_StringObject *)mod_consts.const_str_plain_join_sign, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;

tmp_assign_source_6 = MAKE_FUNCTION_shapes$$$function__2_grid_sum(tstate);

UPDATE_STRING_DICT1(moduledict_shapes, (Nuitka_StringObject *)mod_consts.const_str_plain_grid_sum, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;

tmp_assign_source_7 = MAKE_FUNCTION_shapes$$$function__3_make_scaler(tstate);

UPDATE_STRING_DICT1(moduledict_shapes, (Nuitka_StringObject *)mod_consts.const_str_plain_make_scaler, tmp_assign_source_7);
}
{
PyObject *tmp_assign_source_8;

tmp_assign_source_8 = MAKE_FUNCTION_shapes$$$function__4_lookup(tstate);

UPDATE_STRING_DICT1(moduledict_shapes, (Nuitka_StringObject *)mod_consts.const_str_plain_lookup, tmp_assign_source_8);
}
{
PyObject *tmp_assign_source_9;

tmp_assign_source_9 = MAKE_FUNCTION_shapes$$$function__5_neg_cube(tstate);

UPDATE_STRING_DICT1(moduledict_shapes, (Nuitka_StringObject *)mod_consts.const_str_plain_neg_cube, tmp_assign_source_9);
}
{
PyObject *tmp_assign_source_10;

tmp_assign_source_10 = MAKE_FUNCTION_shapes$$$function__6_neg_power(tstate);

UPDATE_STRING_DICT1(moduledict_shapes, (Nuitka_StringObject *)mod_consts.const_str_plain_neg_power, tmp_assign_source_10);
}
{
PyObject *tmp_assign_source_11;

tmp_assign_source_11 = MAKE_FUNCTION_shapes$$$function__7_either_call(tstate);

UPDATE_STRING_DICT1(moduledict_shapes, (Nuitka_StringObject *)mod_consts.const_str_plain_either_call, tmp_assign_source_11);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("shapes", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "shapes" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_shapes);
    return module_shapes;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_shapes, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("shapes", false);

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
            moduledict_shapes,
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
static struct PyModuleDef mdef_shapes = {
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
            moduledict_shapes,
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

static PyObject *PyInit_shapes_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_shapes(tstate, module, getLoaderEntry("shapes"));

#if PYTHON_VERSION < 0x300
    // Our "__file__" value will not be respected by CPython and one
    // way we can avoid it, is by having a capsule type, that when
    // it gets released, we are called and repair the value.

    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_shapes, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_shapes,
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

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_shapes, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_shapes_slot(PyObject *module) {
    PyObject *result = PyInit_shapes_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_shapes)(void) {
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
    mdef_shapes.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_shapes);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_shapes_slot},
        {0, NULL}
    };

    mdef_shapes.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_shapes);
#elif PYTHON_VERSION >= 0x300
    return PyInit_shapes_phase2(module);
#else
    PyInit_shapes_phase2(module);
#endif
}
