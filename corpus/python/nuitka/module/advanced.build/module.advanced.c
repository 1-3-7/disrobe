/* Generated code for Python module 'advanced'
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



/* The "module_advanced" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_advanced;
PyDictObject *moduledict_advanced;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_int_pos_2;
PyObject *const_str_plain_total;
PyObject *const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12;
PyObject *const_str_plain_inner;
PyObject *const_str_digest_e1b42f9d868fa2d49c3e0de773518e77;
PyObject *const_str_plain_n;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_dict_e17da30d88a5fed360c64d86bc5ef938;
PyObject *const_str_plain_comp;
PyObject *const_dict_a651edb4508386ac796e5d15189d2d4b;
PyObject *const_str_plain_safe_div;
PyObject *const_tuple_int_pos_10_tuple;
PyObject *const_str_plain_with_default;
PyObject *const_dict_999d4fe902b151409bfb710d7c326cfe;
PyObject *const_str_plain_varargs;
PyObject *const_dict_ac2d17ccf098d71f8de0232b23b5a904;
PyObject *const_str_plain_closure;
PyObject *const_dict_08563526dbc3e2676b2f5378f3ebabf0;
PyObject *const_str_plain_dict_comp;
PyObject *const_str_digest_2ee9dfa051556f613a09eee1061b9842;
PyObject *const_str_digest_45679649be31821497b55cac3e8d6030;
PyObject *const_tuple_str_plain_n_str_plain_inner_tuple;
PyObject *const_tuple_str_plain_n_tuple;
PyObject *const_tuple_str_plain_x_str_plain_n_tuple;
PyObject *const_tuple_str_plain_a_str_plain_b_tuple;
PyObject *const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[27];
#endif

static PyObject *module_filename_obj = NULL;

/* Indicator if this modules private constants were created yet. */
static bool constants_created = false;

/* Function to create module private constants. */
static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("advanced"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 27) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 27 values, got %d\n",
                    UN_TRANSLATE("advanced"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_2", mod_consts.const_int_pos_2);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_int_pos_2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_total", mod_consts.const_str_plain_total);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_plain_total);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12", mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_inner", mod_consts.const_str_plain_inner);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_plain_inner);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77", mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_n", mod_consts.const_str_plain_n);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_str_plain_n);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_e17da30d88a5fed360c64d86bc5ef938", mod_consts.const_dict_e17da30d88a5fed360c64d86bc5ef938);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_dict_e17da30d88a5fed360c64d86bc5ef938);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_comp", mod_consts.const_str_plain_comp);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_str_plain_comp);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b", mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_safe_div", mod_consts.const_str_plain_safe_div);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_str_plain_safe_div);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_10_tuple", mod_consts.const_tuple_int_pos_10_tuple);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_10_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_with_default", mod_consts.const_str_plain_with_default);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_str_plain_with_default);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_999d4fe902b151409bfb710d7c326cfe", mod_consts.const_dict_999d4fe902b151409bfb710d7c326cfe);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_dict_999d4fe902b151409bfb710d7c326cfe);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_varargs", mod_consts.const_str_plain_varargs);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_str_plain_varargs);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
mod_consts_hash[16] = DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_closure", mod_consts.const_str_plain_closure);
mod_consts_hash[17] = DEEP_HASH(tstate, mod_consts.const_str_plain_closure);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_08563526dbc3e2676b2f5378f3ebabf0", mod_consts.const_dict_08563526dbc3e2676b2f5378f3ebabf0);
mod_consts_hash[18] = DEEP_HASH(tstate, mod_consts.const_dict_08563526dbc3e2676b2f5378f3ebabf0);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_dict_comp", mod_consts.const_str_plain_dict_comp);
mod_consts_hash[19] = DEEP_HASH(tstate, mod_consts.const_str_plain_dict_comp);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_2ee9dfa051556f613a09eee1061b9842", mod_consts.const_str_digest_2ee9dfa051556f613a09eee1061b9842);
mod_consts_hash[20] = DEEP_HASH(tstate, mod_consts.const_str_digest_2ee9dfa051556f613a09eee1061b9842);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030", mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030);
mod_consts_hash[21] = DEEP_HASH(tstate, mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_inner_tuple", mod_consts.const_tuple_str_plain_n_str_plain_inner_tuple);
mod_consts_hash[22] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_inner_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
mod_consts_hash[23] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_x_str_plain_n_tuple", mod_consts.const_tuple_str_plain_x_str_plain_n_tuple);
mod_consts_hash[24] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_x_str_plain_n_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
mod_consts_hash[25] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple", mod_consts.const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple);
mod_consts_hash[26] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple);
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
void checkModuleConstants_advanced(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_2", mod_consts.const_int_pos_2);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_int_pos_2) && "mod_consts.const_int_pos_2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_total", mod_consts.const_str_plain_total);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_plain_total) && "mod_consts.const_str_plain_total");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12", mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12) && "mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_inner", mod_consts.const_str_plain_inner);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_plain_inner) && "mod_consts.const_str_plain_inner");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77", mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77) && "mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_n", mod_consts.const_str_plain_n);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_str_plain_n) && "mod_consts.const_str_plain_n");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_e17da30d88a5fed360c64d86bc5ef938", mod_consts.const_dict_e17da30d88a5fed360c64d86bc5ef938);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_dict_e17da30d88a5fed360c64d86bc5ef938) && "mod_consts.const_dict_e17da30d88a5fed360c64d86bc5ef938");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_comp", mod_consts.const_str_plain_comp);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_str_plain_comp) && "mod_consts.const_str_plain_comp");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b", mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b) && "mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_safe_div", mod_consts.const_str_plain_safe_div);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_str_plain_safe_div) && "mod_consts.const_str_plain_safe_div");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_10_tuple", mod_consts.const_tuple_int_pos_10_tuple);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_10_tuple) && "mod_consts.const_tuple_int_pos_10_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_with_default", mod_consts.const_str_plain_with_default);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_str_plain_with_default) && "mod_consts.const_str_plain_with_default");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_999d4fe902b151409bfb710d7c326cfe", mod_consts.const_dict_999d4fe902b151409bfb710d7c326cfe);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_dict_999d4fe902b151409bfb710d7c326cfe) && "mod_consts.const_dict_999d4fe902b151409bfb710d7c326cfe");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_varargs", mod_consts.const_str_plain_varargs);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_str_plain_varargs) && "mod_consts.const_str_plain_varargs");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
assert(mod_consts_hash[16] == DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904) && "mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_closure", mod_consts.const_str_plain_closure);
assert(mod_consts_hash[17] == DEEP_HASH(tstate, mod_consts.const_str_plain_closure) && "mod_consts.const_str_plain_closure");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_08563526dbc3e2676b2f5378f3ebabf0", mod_consts.const_dict_08563526dbc3e2676b2f5378f3ebabf0);
assert(mod_consts_hash[18] == DEEP_HASH(tstate, mod_consts.const_dict_08563526dbc3e2676b2f5378f3ebabf0) && "mod_consts.const_dict_08563526dbc3e2676b2f5378f3ebabf0");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_dict_comp", mod_consts.const_str_plain_dict_comp);
assert(mod_consts_hash[19] == DEEP_HASH(tstate, mod_consts.const_str_plain_dict_comp) && "mod_consts.const_str_plain_dict_comp");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_2ee9dfa051556f613a09eee1061b9842", mod_consts.const_str_digest_2ee9dfa051556f613a09eee1061b9842);
assert(mod_consts_hash[20] == DEEP_HASH(tstate, mod_consts.const_str_digest_2ee9dfa051556f613a09eee1061b9842) && "mod_consts.const_str_digest_2ee9dfa051556f613a09eee1061b9842");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030", mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030);
assert(mod_consts_hash[21] == DEEP_HASH(tstate, mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030) && "mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_inner_tuple", mod_consts.const_tuple_str_plain_n_str_plain_inner_tuple);
assert(mod_consts_hash[22] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_inner_tuple) && "mod_consts.const_tuple_str_plain_n_str_plain_inner_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
assert(mod_consts_hash[23] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple) && "mod_consts.const_tuple_str_plain_n_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_x_str_plain_n_tuple", mod_consts.const_tuple_str_plain_x_str_plain_n_tuple);
assert(mod_consts_hash[24] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_x_str_plain_n_tuple) && "mod_consts.const_tuple_str_plain_x_str_plain_n_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
assert(mod_consts_hash[25] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple) && "mod_consts.const_tuple_str_plain_a_str_plain_b_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple", mod_consts.const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple);
assert(mod_consts_hash[26] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple) && "mod_consts.const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple");
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
static PyObject *module_var_accessor_advanced$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_advanced->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_advanced->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_advanced->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_f9988774c2aab6211cd943ce7f32088e;
static PyCodeObject *code_objects_02727c1de560988927ec65447fc19788;
static PyCodeObject *code_objects_57a59383245387996b3be818c53482df;
static PyCodeObject *code_objects_e79f378eda504a7d6584c6e2fbb365cf;
static PyCodeObject *code_objects_77cba545f3b773a780ff1c56cfceae34;
static PyCodeObject *code_objects_31d2d27176f89d4d031bd8dd9de370d5;
static PyCodeObject *code_objects_d525fc3d6fd37786dc21d5f265b624b4;
static PyCodeObject *code_objects_15c7f8b599001af682c0d66a4250e99b;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_2ee9dfa051556f613a09eee1061b9842); CHECK_OBJECT(module_filename_obj);
code_objects_f9988774c2aab6211cd943ce7f32088e = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030, mod_consts.const_str_digest_45679649be31821497b55cac3e8d6030, NULL, NULL, 0, 0, 0);
code_objects_02727c1de560988927ec65447fc19788 = MAKE_CODE_OBJECT(module_filename_obj, 23, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_closure, mod_consts.const_str_plain_closure, mod_consts.const_tuple_str_plain_n_str_plain_inner_tuple, NULL, 1, 0, 0);
code_objects_57a59383245387996b3be818c53482df = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_comp, mod_consts.const_str_plain_comp, mod_consts.const_tuple_str_plain_n_tuple, NULL, 1, 0, 0);
code_objects_e79f378eda504a7d6584c6e2fbb365cf = MAKE_CODE_OBJECT(module_filename_obj, 30, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_dict_comp, mod_consts.const_str_plain_dict_comp, mod_consts.const_tuple_str_plain_n_tuple, NULL, 1, 0, 0);
code_objects_77cba545f3b773a780ff1c56cfceae34 = MAKE_CODE_OBJECT(module_filename_obj, 24, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_inner, mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77, mod_consts.const_tuple_str_plain_x_str_plain_n_tuple, mod_consts.const_tuple_str_plain_n_tuple, 1, 0, 0);
code_objects_31d2d27176f89d4d031bd8dd9de370d5 = MAKE_CODE_OBJECT(module_filename_obj, 5, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_safe_div, mod_consts.const_str_plain_safe_div, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple, NULL, 2, 0, 0);
code_objects_d525fc3d6fd37786dc21d5f265b624b4 = MAKE_CODE_OBJECT(module_filename_obj, 16, CO_OPTIMIZED | CO_NEWLOCALS | CO_VARARGS, mod_consts.const_str_plain_varargs, mod_consts.const_str_plain_varargs, mod_consts.const_tuple_str_plain_nums_str_plain_total_str_plain_x_tuple, NULL, 0, 0, 0);
code_objects_15c7f8b599001af682c0d66a4250e99b = MAKE_CODE_OBJECT(module_filename_obj, 12, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_with_default, mod_consts.const_str_plain_with_default, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple, NULL, 2, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION_advanced$$$function__1_comp(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_advanced$$$function__2_safe_div(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_advanced$$$function__3_with_default(PyThreadState *tstate, PyObject *defaults, PyObject *annotations);


static PyObject *MAKE_FUNCTION_advanced$$$function__4_varargs(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_advanced$$$function__5_closure(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_advanced$$$function__5_closure$$$function__1_inner(PyThreadState *tstate, PyObject *annotations, struct Nuitka_CellObject **closure);


static PyObject *MAKE_FUNCTION_advanced$$$function__6_dict_comp(PyThreadState *tstate, PyObject *annotations);


// The module function definitions.
static PyObject *impl_advanced$$$function__1_comp(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_n = python_pars[0];
PyObject *outline_0_var_i = NULL;
PyObject *tmp_listcomp_1__$0 = NULL;
PyObject *tmp_listcomp_1__contraction = NULL;
PyObject *tmp_listcomp_1__iter_value_0 = NULL;
struct Nuitka_FrameObject *frame_frame_advanced$$$function__1_comp;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
static struct Nuitka_FrameObject *cache_frame_frame_advanced$$$function__1_comp = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_advanced$$$function__1_comp)) {
    Py_XDECREF(cache_frame_frame_advanced$$$function__1_comp);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_advanced$$$function__1_comp == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_advanced$$$function__1_comp = MAKE_FUNCTION_FRAME(tstate, code_objects_57a59383245387996b3be818c53482df, module_advanced, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_advanced$$$function__1_comp->m_type_description == NULL);
frame_frame_advanced$$$function__1_comp = cache_frame_frame_advanced$$$function__1_comp;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_advanced$$$function__1_comp);
assert(Py_REFCNT(frame_frame_advanced$$$function__1_comp) == 2);

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


exception_lineno = 2;
type_description_1 = "o";
    goto try_except_handler_1;
}
tmp_assign_source_1 = MAKE_ITERATOR(tstate, tmp_iter_arg_1);
CHECK_OBJECT(tmp_iter_arg_1);
Py_DECREF(tmp_iter_arg_1);
if (tmp_assign_source_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "o";
    goto try_except_handler_1;
}
{
    PyObject *old = tmp_listcomp_1__$0;
    tmp_listcomp_1__$0 = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = MAKE_LIST_EMPTY(tstate, 0);
{
    PyObject *old = tmp_listcomp_1__contraction;
    tmp_listcomp_1__contraction = tmp_assign_source_2;
    Py_XDECREF(old);
}

}
// Tried code:
loop_start_1:;
{
PyObject *tmp_next_source_1;
PyObject *tmp_assign_source_3;
CHECK_OBJECT(tmp_listcomp_1__$0);
tmp_next_source_1 = tmp_listcomp_1__$0;
tmp_assign_source_3 = ITERATOR_NEXT_ITERATOR(tmp_next_source_1);
if (tmp_assign_source_3 == NULL) {
    if (CHECK_AND_CLEAR_STOP_ITERATION_OCCURRED(tstate)) {

        goto loop_end_1;
    } else {

        FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
type_description_1 = "o";
exception_lineno = 2;
        goto try_except_handler_2;
    }
}

{
    PyObject *old = tmp_listcomp_1__iter_value_0;
    tmp_listcomp_1__iter_value_0 = tmp_assign_source_3;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_4;
CHECK_OBJECT(tmp_listcomp_1__iter_value_0);
tmp_assign_source_4 = tmp_listcomp_1__iter_value_0;
{
    PyObject *old = outline_0_var_i;
    outline_0_var_i = tmp_assign_source_4;
    Py_INCREF(outline_0_var_i);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_append_list_1;
PyObject *tmp_append_value_1;
PyObject *tmp_mult_expr_left_1;
PyObject *tmp_mult_expr_right_1;
CHECK_OBJECT(tmp_listcomp_1__contraction);
tmp_append_list_1 = tmp_listcomp_1__contraction;
CHECK_OBJECT(outline_0_var_i);
tmp_mult_expr_left_1 = outline_0_var_i;
tmp_mult_expr_right_1 = mod_consts.const_int_pos_2;
tmp_append_value_1 = BINARY_OPERATION_MULT_OBJECT_OBJECT_LONG(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
if (tmp_append_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "o";
    goto try_except_handler_2;
}
tmp_result = LIST_APPEND1(tmp_append_list_1, tmp_append_value_1);
if (tmp_result == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "o";
    goto try_except_handler_2;
}
}
if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "o";
    goto try_except_handler_2;
}
goto loop_start_1;
loop_end_1:;
CHECK_OBJECT(tmp_listcomp_1__contraction);
tmp_return_value = tmp_listcomp_1__contraction;
Py_INCREF(tmp_return_value);
goto try_return_handler_2;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_2:;
CHECK_OBJECT(tmp_listcomp_1__$0);
CHECK_OBJECT(tmp_listcomp_1__$0);
Py_DECREF(tmp_listcomp_1__$0);
tmp_listcomp_1__$0 = NULL;
CHECK_OBJECT(tmp_listcomp_1__contraction);
CHECK_OBJECT(tmp_listcomp_1__contraction);
Py_DECREF(tmp_listcomp_1__contraction);
tmp_listcomp_1__contraction = NULL;
Py_XDECREF(tmp_listcomp_1__iter_value_0);
tmp_listcomp_1__iter_value_0 = NULL;
goto try_return_handler_1;
// Exception handler code:
try_except_handler_2:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(tmp_listcomp_1__$0);
CHECK_OBJECT(tmp_listcomp_1__$0);
Py_DECREF(tmp_listcomp_1__$0);
tmp_listcomp_1__$0 = NULL;
CHECK_OBJECT(tmp_listcomp_1__contraction);
CHECK_OBJECT(tmp_listcomp_1__contraction);
Py_DECREF(tmp_listcomp_1__contraction);
tmp_listcomp_1__contraction = NULL;
Py_XDECREF(tmp_listcomp_1__iter_value_0);
tmp_listcomp_1__iter_value_0 = NULL;
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
exception_lineno = 2;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced$$$function__1_comp, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_advanced$$$function__1_comp->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced$$$function__1_comp, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_advanced$$$function__1_comp,
    type_description_1,
    par_n
);


// Release cached frame if used for exception.
if (frame_frame_advanced$$$function__1_comp == cache_frame_frame_advanced$$$function__1_comp) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_advanced$$$function__1_comp);
    cache_frame_frame_advanced$$$function__1_comp = NULL;
}

assertFrameObject(frame_frame_advanced$$$function__1_comp);

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


static PyObject *impl_advanced$$$function__2_safe_div(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
struct Nuitka_FrameObject *frame_frame_advanced$$$function__2_safe_div;
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
static struct Nuitka_FrameObject *cache_frame_frame_advanced$$$function__2_safe_div = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_advanced$$$function__2_safe_div)) {
    Py_XDECREF(cache_frame_frame_advanced$$$function__2_safe_div);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_advanced$$$function__2_safe_div == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_advanced$$$function__2_safe_div = MAKE_FUNCTION_FRAME(tstate, code_objects_31d2d27176f89d4d031bd8dd9de370d5, module_advanced, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_advanced$$$function__2_safe_div->m_type_description == NULL);
frame_frame_advanced$$$function__2_safe_div = cache_frame_frame_advanced$$$function__2_safe_div;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_advanced$$$function__2_safe_div);
assert(Py_REFCNT(frame_frame_advanced$$$function__2_safe_div) == 2);

// Framed code:
// Tried code:
{
PyObject *tmp_floordiv_expr_left_1;
PyObject *tmp_floordiv_expr_right_1;
CHECK_OBJECT(par_a);
tmp_floordiv_expr_left_1 = par_a;
CHECK_OBJECT(par_b);
tmp_floordiv_expr_right_1 = par_b;
tmp_return_value = BINARY_OPERATION_FLOORDIV_OBJECT_OBJECT_OBJECT(tmp_floordiv_expr_left_1, tmp_floordiv_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 7;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced$$$function__2_safe_div, exception_keeper_lineno_1);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_keeper_name_1, exception_tb);
    } else if (exception_keeper_lineno_1 != 0) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced$$$function__2_safe_div, exception_keeper_lineno_1);
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
tmp_cmp_expr_right_1 = PyExc_ZeroDivisionError;
tmp_res = EXCEPTION_MATCH_BOOL(tstate, tmp_cmp_expr_left_1, tmp_cmp_expr_right_1);
assert(!(tmp_res == -1));
tmp_condition_result_1 = (tmp_res != 0) ? true : false;
if (tmp_condition_result_1 != false) {
    goto branch_yes_1;
} else {
    goto branch_no_1;
}
}
branch_yes_1:;
tmp_return_value = const_int_0;
Py_INCREF_IMMORTAL(tmp_return_value);
goto try_return_handler_2;
goto branch_end_1;
branch_no_1:;
tmp_result = RERAISE_EXCEPTION(tstate, &exception_state);
if (unlikely(tmp_result == false)) {
    exception_lineno = 6;
}

{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);

    if ((exception_tb != NULL) && (exception_tb->tb_frame == &frame_frame_advanced$$$function__2_safe_div->m_frame)) {
        frame_frame_advanced$$$function__2_safe_div->m_frame.f_lineno = exception_tb->tb_lineno;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced$$$function__2_safe_div, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_advanced$$$function__2_safe_div->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced$$$function__2_safe_div, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_advanced$$$function__2_safe_div,
    type_description_1,
    par_a,
    par_b
);


// Release cached frame if used for exception.
if (frame_frame_advanced$$$function__2_safe_div == cache_frame_frame_advanced$$$function__2_safe_div) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_advanced$$$function__2_safe_div);
    cache_frame_frame_advanced$$$function__2_safe_div = NULL;
}

assertFrameObject(frame_frame_advanced$$$function__2_safe_div);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_a);
Py_DECREF(par_a);
CHECK_OBJECT(par_b);
Py_DECREF(par_b);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_a);
Py_DECREF(par_a);
CHECK_OBJECT(par_b);
Py_DECREF(par_b);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_advanced$$$function__3_with_default(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
struct Nuitka_FrameObject *frame_frame_advanced$$$function__3_with_default;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_advanced$$$function__3_with_default = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_advanced$$$function__3_with_default)) {
    Py_XDECREF(cache_frame_frame_advanced$$$function__3_with_default);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_advanced$$$function__3_with_default == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_advanced$$$function__3_with_default = MAKE_FUNCTION_FRAME(tstate, code_objects_15c7f8b599001af682c0d66a4250e99b, module_advanced, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_advanced$$$function__3_with_default->m_type_description == NULL);
frame_frame_advanced$$$function__3_with_default = cache_frame_frame_advanced$$$function__3_with_default;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_advanced$$$function__3_with_default);
assert(Py_REFCNT(frame_frame_advanced$$$function__3_with_default) == 2);

// Framed code:
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
CHECK_OBJECT(par_a);
tmp_add_expr_left_1 = par_a;
CHECK_OBJECT(par_b);
tmp_add_expr_right_1 = par_b;
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 13;
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

goto function_return_exit;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced$$$function__3_with_default, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_advanced$$$function__3_with_default->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced$$$function__3_with_default, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_advanced$$$function__3_with_default,
    type_description_1,
    par_a,
    par_b
);


// Release cached frame if used for exception.
if (frame_frame_advanced$$$function__3_with_default == cache_frame_frame_advanced$$$function__3_with_default) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_advanced$$$function__3_with_default);
    cache_frame_frame_advanced$$$function__3_with_default = NULL;
}

assertFrameObject(frame_frame_advanced$$$function__3_with_default);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_a);
Py_DECREF(par_a);
CHECK_OBJECT(par_b);
Py_DECREF(par_b);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_a);
Py_DECREF(par_a);
CHECK_OBJECT(par_b);
Py_DECREF(par_b);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_advanced$$$function__4_varargs(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_nums = python_pars[0];
PyObject *var_total = NULL;
PyObject *var_x = NULL;
PyObject *tmp_for_loop_1__for_iterator = NULL;
PyObject *tmp_for_loop_1__iter_value = NULL;
struct Nuitka_FrameObject *frame_frame_advanced$$$function__4_varargs;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
PyObject *tmp_return_value = NULL;
static struct Nuitka_FrameObject *cache_frame_frame_advanced$$$function__4_varargs = NULL;
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
if (isFrameUnusable(cache_frame_frame_advanced$$$function__4_varargs)) {
    Py_XDECREF(cache_frame_frame_advanced$$$function__4_varargs);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_advanced$$$function__4_varargs == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_advanced$$$function__4_varargs = MAKE_FUNCTION_FRAME(tstate, code_objects_d525fc3d6fd37786dc21d5f265b624b4, module_advanced, sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_advanced$$$function__4_varargs->m_type_description == NULL);
frame_frame_advanced$$$function__4_varargs = cache_frame_frame_advanced$$$function__4_varargs;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_advanced$$$function__4_varargs);
assert(Py_REFCNT(frame_frame_advanced$$$function__4_varargs) == 2);

// Framed code:
{
PyObject *tmp_assign_source_2;
PyObject *tmp_iter_arg_1;
CHECK_OBJECT(par_nums);
tmp_iter_arg_1 = par_nums;
tmp_assign_source_2 = MAKE_ITERATOR(tstate, tmp_iter_arg_1);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 18;
type_description_1 = "ooo";
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
type_description_1 = "ooo";
exception_lineno = 18;
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
    PyObject *old = var_x;
    var_x = tmp_assign_source_4;
    Py_INCREF(var_x);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
if (var_total == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_total);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 19;
type_description_1 = "ooo";
    goto try_except_handler_2;
}

tmp_add_expr_left_1 = var_total;
CHECK_OBJECT(var_x);
tmp_add_expr_right_1 = var_x;
tmp_assign_source_5 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_assign_source_5 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 19;
type_description_1 = "ooo";
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


exception_lineno = 18;
type_description_1 = "ooo";
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

exception_lineno = 20;
type_description_1 = "ooo";
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
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced$$$function__4_varargs, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_advanced$$$function__4_varargs->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced$$$function__4_varargs, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_advanced$$$function__4_varargs,
    type_description_1,
    par_nums,
    var_total,
    var_x
);


// Release cached frame if used for exception.
if (frame_frame_advanced$$$function__4_varargs == cache_frame_frame_advanced$$$function__4_varargs) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_advanced$$$function__4_varargs);
    cache_frame_frame_advanced$$$function__4_varargs = NULL;
}

assertFrameObject(frame_frame_advanced$$$function__4_varargs);

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
Py_XDECREF(var_x);
var_x = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_2 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_2 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_total);
var_total = NULL;
Py_XDECREF(var_x);
var_x = NULL;
// Re-raise.
exception_state = exception_keeper_name_2;
exception_lineno = exception_keeper_lineno_2;

goto function_exception_exit;
// End of try:

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_nums);
Py_DECREF(par_nums);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_nums);
Py_DECREF(par_nums);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_advanced$$$function__5_closure(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
struct Nuitka_CellObject *par_n = Nuitka_Cell_New1(python_pars[0]);
PyObject *var_inner = NULL;
struct Nuitka_FrameObject *frame_frame_advanced$$$function__5_closure;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_advanced$$$function__5_closure = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;

    // Actual function body.
{
PyObject *tmp_assign_source_1;
PyObject *tmp_annotations_1;
struct Nuitka_CellObject *tmp_closure_1[1];
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12);
tmp_closure_1[0] = par_n;
Py_INCREF(tmp_closure_1[0]);
tmp_assign_source_1 = MAKE_FUNCTION_advanced$$$function__5_closure$$$function__1_inner(tstate, tmp_annotations_1, tmp_closure_1);

{
    PyObject *old = var_inner;
    var_inner = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
// Tried code:
if (isFrameUnusable(cache_frame_frame_advanced$$$function__5_closure)) {
    Py_XDECREF(cache_frame_frame_advanced$$$function__5_closure);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_advanced$$$function__5_closure == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_advanced$$$function__5_closure = MAKE_FUNCTION_FRAME(tstate, code_objects_02727c1de560988927ec65447fc19788, module_advanced, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_advanced$$$function__5_closure->m_type_description == NULL);
frame_frame_advanced$$$function__5_closure = cache_frame_frame_advanced$$$function__5_closure;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_advanced$$$function__5_closure);
assert(Py_REFCNT(frame_frame_advanced$$$function__5_closure) == 2);

// Framed code:
{
PyObject *tmp_called_value_1;
PyObject *tmp_args_element_value_1;
CHECK_OBJECT(var_inner);
tmp_called_value_1 = var_inner;
CHECK_OBJECT(Nuitka_Cell_GET(par_n));
tmp_args_element_value_1 = Nuitka_Cell_GET(par_n);
frame_frame_advanced$$$function__5_closure->m_frame.f_lineno = 27;
tmp_return_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_1, tmp_args_element_value_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 27;
type_description_1 = "co";
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
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced$$$function__5_closure, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_advanced$$$function__5_closure->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced$$$function__5_closure, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_advanced$$$function__5_closure,
    type_description_1,
    par_n,
    var_inner
);


// Release cached frame if used for exception.
if (frame_frame_advanced$$$function__5_closure == cache_frame_frame_advanced$$$function__5_closure) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_advanced$$$function__5_closure);
    cache_frame_frame_advanced$$$function__5_closure = NULL;
}

assertFrameObject(frame_frame_advanced$$$function__5_closure);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
CHECK_OBJECT(par_n);
CHECK_OBJECT(par_n);
Py_DECREF(par_n);
par_n = NULL;
CHECK_OBJECT(var_inner);
CHECK_OBJECT(var_inner);
Py_DECREF(var_inner);
var_inner = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(par_n);
CHECK_OBJECT(par_n);
Py_DECREF(par_n);
par_n = NULL;
CHECK_OBJECT(var_inner);
CHECK_OBJECT(var_inner);
Py_DECREF(var_inner);
var_inner = NULL;
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


static PyObject *impl_advanced$$$function__5_closure$$$function__1_inner(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_x = python_pars[0];
struct Nuitka_FrameObject *frame_frame_advanced$$$function__5_closure$$$function__1_inner;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner)) {
    Py_XDECREF(cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner = MAKE_FUNCTION_FRAME(tstate, code_objects_77cba545f3b773a780ff1c56cfceae34, module_advanced, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner->m_type_description == NULL);
frame_frame_advanced$$$function__5_closure$$$function__1_inner = cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_advanced$$$function__5_closure$$$function__1_inner);
assert(Py_REFCNT(frame_frame_advanced$$$function__5_closure$$$function__1_inner) == 2);

// Framed code:
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
CHECK_OBJECT(par_x);
tmp_add_expr_left_1 = par_x;
if (Nuitka_Cell_GET(self->m_closure[0]) == NULL) {

FORMAT_UNBOUND_CLOSURE_ERROR(tstate, &exception_state, mod_consts.const_str_plain_n);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 25;
type_description_1 = "oc";
    goto frame_exception_exit_1;
}

tmp_add_expr_right_1 = Nuitka_Cell_GET(self->m_closure[0]);
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 25;
type_description_1 = "oc";
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
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced$$$function__5_closure$$$function__1_inner, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_advanced$$$function__5_closure$$$function__1_inner->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced$$$function__5_closure$$$function__1_inner, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_advanced$$$function__5_closure$$$function__1_inner,
    type_description_1,
    par_x,
    self->m_closure[0]
);


// Release cached frame if used for exception.
if (frame_frame_advanced$$$function__5_closure$$$function__1_inner == cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner);
    cache_frame_frame_advanced$$$function__5_closure$$$function__1_inner = NULL;
}

assertFrameObject(frame_frame_advanced$$$function__5_closure$$$function__1_inner);

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


static PyObject *impl_advanced$$$function__6_dict_comp(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
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
struct Nuitka_FrameObject *frame_frame_advanced$$$function__6_dict_comp;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
int tmp_res;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
static struct Nuitka_FrameObject *cache_frame_frame_advanced$$$function__6_dict_comp = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_advanced$$$function__6_dict_comp)) {
    Py_XDECREF(cache_frame_frame_advanced$$$function__6_dict_comp);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_advanced$$$function__6_dict_comp == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_advanced$$$function__6_dict_comp = MAKE_FUNCTION_FRAME(tstate, code_objects_e79f378eda504a7d6584c6e2fbb365cf, module_advanced, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_advanced$$$function__6_dict_comp->m_type_description == NULL);
frame_frame_advanced$$$function__6_dict_comp = cache_frame_frame_advanced$$$function__6_dict_comp;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_advanced$$$function__6_dict_comp);
assert(Py_REFCNT(frame_frame_advanced$$$function__6_dict_comp) == 2);

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


exception_lineno = 31;
type_description_1 = "o";
    goto try_except_handler_1;
}
tmp_assign_source_1 = MAKE_ITERATOR(tstate, tmp_iter_arg_1);
CHECK_OBJECT(tmp_iter_arg_1);
Py_DECREF(tmp_iter_arg_1);
if (tmp_assign_source_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 31;
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
exception_lineno = 31;
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


exception_lineno = 31;
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


exception_lineno = 31;
type_description_1 = "o";
    goto try_except_handler_2;
}
}
if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 31;
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
exception_lineno = 31;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced$$$function__6_dict_comp, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_advanced$$$function__6_dict_comp->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced$$$function__6_dict_comp, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_advanced$$$function__6_dict_comp,
    type_description_1,
    par_n
);


// Release cached frame if used for exception.
if (frame_frame_advanced$$$function__6_dict_comp == cache_frame_frame_advanced$$$function__6_dict_comp) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_advanced$$$function__6_dict_comp);
    cache_frame_frame_advanced$$$function__6_dict_comp = NULL;
}

assertFrameObject(frame_frame_advanced$$$function__6_dict_comp);

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



static PyObject *MAKE_FUNCTION_advanced$$$function__1_comp(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_advanced$$$function__1_comp,
        mod_consts.const_str_plain_comp,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_57a59383245387996b3be818c53482df,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_advanced,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_advanced$$$function__2_safe_div(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_advanced$$$function__2_safe_div,
        mod_consts.const_str_plain_safe_div,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_31d2d27176f89d4d031bd8dd9de370d5,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_advanced,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_advanced$$$function__3_with_default(PyThreadState *tstate, PyObject *defaults, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_advanced$$$function__3_with_default,
        mod_consts.const_str_plain_with_default,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_15c7f8b599001af682c0d66a4250e99b,
        defaults,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_advanced,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_advanced$$$function__4_varargs(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_advanced$$$function__4_varargs,
        mod_consts.const_str_plain_varargs,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_d525fc3d6fd37786dc21d5f265b624b4,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_advanced,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_advanced$$$function__5_closure(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_advanced$$$function__5_closure,
        mod_consts.const_str_plain_closure,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_02727c1de560988927ec65447fc19788,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_advanced,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_advanced$$$function__5_closure$$$function__1_inner(PyThreadState *tstate, PyObject *annotations, struct Nuitka_CellObject **closure) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_advanced$$$function__5_closure$$$function__1_inner,
        mod_consts.const_str_plain_inner,
#if PYTHON_VERSION >= 0x300
        mod_consts.const_str_digest_e1b42f9d868fa2d49c3e0de773518e77,
#endif
        code_objects_77cba545f3b773a780ff1c56cfceae34,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_advanced,
        NULL,
        closure,
        1
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_advanced$$$function__6_dict_comp(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_advanced$$$function__6_dict_comp,
        mod_consts.const_str_plain_dict_comp,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_e79f378eda504a7d6584c6e2fbb365cf,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_advanced,
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

static function_impl_code const function_table_advanced[] = {
impl_advanced$$$function__5_closure$$$function__1_inner,
impl_advanced$$$function__1_comp,
impl_advanced$$$function__2_safe_div,
impl_advanced$$$function__3_with_default,
impl_advanced$$$function__4_varargs,
impl_advanced$$$function__5_closure,
impl_advanced$$$function__6_dict_comp,
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

    return Nuitka_Function_GetFunctionState(function, function_table_advanced);
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
        module_advanced,
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
        function_table_advanced,
        sizeof(function_table_advanced) / sizeof(function_impl_code)
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
static char const *module_full_name = "advanced";
#endif

// Internal entry point for module code.
PyObject *module_code_advanced(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("advanced");

    // Store the module for future use.
    module_advanced = module;

    moduledict_advanced = MODULE_DICT(module_advanced);

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
        PRINT_STRING("advanced: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("advanced: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("advanced: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "advanced" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initadvanced\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict_advanced,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_advanced,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_advanced,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_advanced,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_advanced,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_advanced);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_advanced);
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

        UPDATE_STRING_DICT1(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_advanced;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_advanced = MAKE_MODULE_FRAME(code_objects_f9988774c2aab6211cd943ce7f32088e, module_advanced);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_advanced);
assert(Py_REFCNT(frame_frame_advanced) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_advanced$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_advanced$__spec__(tstate);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_advanced, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_advanced->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_advanced, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_advanced);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_annotations_1;
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_e17da30d88a5fed360c64d86bc5ef938);

tmp_assign_source_5 = MAKE_FUNCTION_advanced$$$function__1_comp(tstate, tmp_annotations_1);

UPDATE_STRING_DICT1(moduledict_advanced, (Nuitka_StringObject *)mod_consts.const_str_plain_comp, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
PyObject *tmp_annotations_2;
tmp_annotations_2 = DICT_COPY(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);

tmp_assign_source_6 = MAKE_FUNCTION_advanced$$$function__2_safe_div(tstate, tmp_annotations_2);

UPDATE_STRING_DICT1(moduledict_advanced, (Nuitka_StringObject *)mod_consts.const_str_plain_safe_div, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;
PyObject *tmp_defaults_1;
PyObject *tmp_annotations_3;
tmp_defaults_1 = mod_consts.const_tuple_int_pos_10_tuple;
tmp_annotations_3 = DICT_COPY(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
Py_INCREF(tmp_defaults_1);

tmp_assign_source_7 = MAKE_FUNCTION_advanced$$$function__3_with_default(tstate, tmp_defaults_1, tmp_annotations_3);

UPDATE_STRING_DICT1(moduledict_advanced, (Nuitka_StringObject *)mod_consts.const_str_plain_with_default, tmp_assign_source_7);
}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_annotations_4;
tmp_annotations_4 = DICT_COPY(tstate, mod_consts.const_dict_999d4fe902b151409bfb710d7c326cfe);

tmp_assign_source_8 = MAKE_FUNCTION_advanced$$$function__4_varargs(tstate, tmp_annotations_4);

UPDATE_STRING_DICT1(moduledict_advanced, (Nuitka_StringObject *)mod_consts.const_str_plain_varargs, tmp_assign_source_8);
}
{
PyObject *tmp_assign_source_9;
PyObject *tmp_annotations_5;
tmp_annotations_5 = DICT_COPY(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);

tmp_assign_source_9 = MAKE_FUNCTION_advanced$$$function__5_closure(tstate, tmp_annotations_5);

UPDATE_STRING_DICT1(moduledict_advanced, (Nuitka_StringObject *)mod_consts.const_str_plain_closure, tmp_assign_source_9);
}
{
PyObject *tmp_assign_source_10;
PyObject *tmp_annotations_6;
tmp_annotations_6 = DICT_COPY(tstate, mod_consts.const_dict_08563526dbc3e2676b2f5378f3ebabf0);

tmp_assign_source_10 = MAKE_FUNCTION_advanced$$$function__6_dict_comp(tstate, tmp_annotations_6);

UPDATE_STRING_DICT1(moduledict_advanced, (Nuitka_StringObject *)mod_consts.const_str_plain_dict_comp, tmp_assign_source_10);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("advanced", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "advanced" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_advanced);
    return module_advanced;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_advanced, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("advanced", false);

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
            moduledict_advanced,
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
static struct PyModuleDef mdef_advanced = {
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
            moduledict_advanced,
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

static PyObject *PyInit_advanced_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_advanced(tstate, module, getLoaderEntry("advanced"));

#if PYTHON_VERSION < 0x300
    // Our "__file__" value will not be respected by CPython and one
    // way we can avoid it, is by having a capsule type, that when
    // it gets released, we are called and repair the value.

    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_advanced, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_advanced,
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

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_advanced, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_advanced_slot(PyObject *module) {
    PyObject *result = PyInit_advanced_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_advanced)(void) {
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
    mdef_advanced.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_advanced);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_advanced_slot},
        {0, NULL}
    };

    mdef_advanced.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_advanced);
#elif PYTHON_VERSION >= 0x300
    return PyInit_advanced_phase2(module);
#else
    PyInit_advanced_phase2(module);
#endif
}
