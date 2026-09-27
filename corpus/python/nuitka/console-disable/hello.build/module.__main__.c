/* Generated code for Python module '__main__'
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



/* The "module___main__" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module___main__;
PyDictObject *moduledict___main__;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_str_digest_9ee70a5c303845daec9e23bee0b001a7;
PyObject *const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7;
PyObject *const_str_plain_MARKER;
PyObject *const_str_chr_93;
PyObject *const_int_pos_2;
PyObject *const_tuple_int_0_int_pos_1_tuple;
PyObject *const_str_plain_a;
PyObject *const_str_plain_greet;
PyObject *const_tuple_str_plain_disrobe_tuple;
PyObject *const_str_plain_fib;
PyObject *const_tuple_int_pos_20_tuple;
PyObject *const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0;
PyObject *const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c;
PyObject *const_dict_0d747635c5b87742d1bd242db31edac3;
PyObject *const_dict_ac2d17ccf098d71f8de0232b23b5a904;
PyObject *const_dict_1259841a0de68bdf7d5f55bbd030b617;
PyObject *const_str_plain_main;
PyObject *const_str_angle_module;
PyObject *const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple;
PyObject *const_tuple_str_plain_name_tuple;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[20];
#endif

static PyObject *module_filename_obj = NULL;

/* Indicator if this modules private constants were created yet. */
static bool constants_created = false;

/* Function to create module private constants. */
static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("__main__"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 20) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 20 values, got %d\n",
                    UN_TRANSLATE("__main__"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7", mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7", mod_consts.const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_MARKER", mod_consts.const_str_plain_MARKER);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_str_plain_MARKER);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_chr_93", mod_consts.const_str_chr_93);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_chr_93);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_2", mod_consts.const_int_pos_2);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_int_pos_2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_0_int_pos_1_tuple", mod_consts.const_tuple_int_0_int_pos_1_tuple);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_tuple_int_0_int_pos_1_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_a", mod_consts.const_str_plain_a);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_plain_a);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_greet", mod_consts.const_str_plain_greet);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_str_plain_greet);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_disrobe_tuple", mod_consts.const_tuple_str_plain_disrobe_tuple);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_disrobe_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_fib", mod_consts.const_str_plain_fib);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_str_plain_fib);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_20_tuple", mod_consts.const_tuple_int_pos_20_tuple);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_20_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0", mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c", mod_consts.const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3", mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617", mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_main", mod_consts.const_str_plain_main);
mod_consts_hash[16] = DEEP_HASH(tstate, mod_consts.const_str_plain_main);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_angle_module", mod_consts.const_str_angle_module);
mod_consts_hash[17] = DEEP_HASH(tstate, mod_consts.const_str_angle_module);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple", mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
mod_consts_hash[18] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_name_tuple", mod_consts.const_tuple_str_plain_name_tuple);
mod_consts_hash[19] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_name_tuple);
#endif
    }
}

// We want to be able to initialize the "__main__" constants in any case.
#if 1
void createMainModuleConstants(PyThreadState *tstate) {
    createModuleConstants(tstate);
}
#endif

/* Function to verify module private constants for non-corruption. */
#ifndef __NUITKA_NO_ASSERT__
void checkModuleConstants___main__(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7", mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7) && "mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7", mod_consts.const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7) && "mod_consts.const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_MARKER", mod_consts.const_str_plain_MARKER);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_str_plain_MARKER) && "mod_consts.const_str_plain_MARKER");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_chr_93", mod_consts.const_str_chr_93);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_chr_93) && "mod_consts.const_str_chr_93");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_2", mod_consts.const_int_pos_2);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_int_pos_2) && "mod_consts.const_int_pos_2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_0_int_pos_1_tuple", mod_consts.const_tuple_int_0_int_pos_1_tuple);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_tuple_int_0_int_pos_1_tuple) && "mod_consts.const_tuple_int_0_int_pos_1_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_a", mod_consts.const_str_plain_a);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_plain_a) && "mod_consts.const_str_plain_a");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_greet", mod_consts.const_str_plain_greet);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_str_plain_greet) && "mod_consts.const_str_plain_greet");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_disrobe_tuple", mod_consts.const_tuple_str_plain_disrobe_tuple);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_disrobe_tuple) && "mod_consts.const_tuple_str_plain_disrobe_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_fib", mod_consts.const_str_plain_fib);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_str_plain_fib) && "mod_consts.const_str_plain_fib");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_20_tuple", mod_consts.const_tuple_int_pos_20_tuple);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_20_tuple) && "mod_consts.const_tuple_int_pos_20_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0", mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0) && "mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c", mod_consts.const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c) && "mod_consts.const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3", mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3) && "mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904) && "mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617", mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617) && "mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_main", mod_consts.const_str_plain_main);
assert(mod_consts_hash[16] == DEEP_HASH(tstate, mod_consts.const_str_plain_main) && "mod_consts.const_str_plain_main");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_angle_module", mod_consts.const_str_angle_module);
assert(mod_consts_hash[17] == DEEP_HASH(tstate, mod_consts.const_str_angle_module) && "mod_consts.const_str_angle_module");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple", mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
assert(mod_consts_hash[18] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple) && "mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_name_tuple", mod_consts.const_tuple_str_plain_name_tuple);
assert(mod_consts_hash[19] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_name_tuple) && "mod_consts.const_tuple_str_plain_name_tuple");
}
#endif

// Helper to preserving module variables for Python3.11+
#if 4
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
static PyObject *module_var_accessor___main__$MARKER(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict___main__->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict___main__->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_MARKER);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict___main__->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_MARKER);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_MARKER, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_MARKER);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_MARKER, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_MARKER);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_MARKER);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_MARKER);
    }

    return result;
}

static PyObject *module_var_accessor___main__$fib(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict___main__->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict___main__->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict___main__->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
    }

    return result;
}

static PyObject *module_var_accessor___main__$greet(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict___main__->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict___main__->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict___main__->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
    }

    return result;
}

static PyObject *module_var_accessor___main__$main(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict___main__->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict___main__->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_main);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict___main__->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_main);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_main, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(mod_consts.const_str_plain_main);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, mod_consts.const_str_plain_main, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_main);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_main);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_main);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_36c4fffdf4652f37ce17487e09cbaccb;
static PyCodeObject *code_objects_0bb3047bc620f1098daa8345034651f8;
static PyCodeObject *code_objects_83a2583323fc2cfc712dc6af57219eb8;
static PyCodeObject *code_objects_31194cfd0811358daf03c7129c3e07b7;
/* For use in "MainProgram.c". */
PyCodeObject *code_objects_main = NULL;

static void createModuleCodeObjects(void) {
module_filename_obj = mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0; CHECK_OBJECT(module_filename_obj);
code_objects_36c4fffdf4652f37ce17487e09cbaccb = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_angle_module, mod_consts.const_str_angle_module, NULL, NULL, 0, 0, 0);
code_objects_main = code_objects_36c4fffdf4652f37ce17487e09cbaccb;
code_objects_0bb3047bc620f1098daa8345034651f8 = MAKE_CODE_OBJECT(module_filename_obj, 8, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_fib, mod_consts.const_str_plain_fib, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple, NULL, 1, 0, 0);
code_objects_83a2583323fc2cfc712dc6af57219eb8 = MAKE_CODE_OBJECT(module_filename_obj, 4, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_greet, mod_consts.const_str_plain_greet, mod_consts.const_tuple_str_plain_name_tuple, NULL, 1, 0, 0);
code_objects_31194cfd0811358daf03c7129c3e07b7 = MAKE_CODE_OBJECT(module_filename_obj, 17, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_main, mod_consts.const_str_plain_main, NULL, NULL, 0, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION___main__$$$function__1_greet(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION___main__$$$function__2_fib(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION___main__$$$function__3_main(PyThreadState *tstate, PyObject *annotations);


// The module function definitions.
static PyObject *impl___main__$$$function__1_greet(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_name = python_pars[0];
struct Nuitka_FrameObject *frame_frame___main__$$$function__1_greet;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame___main__$$$function__1_greet = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame___main__$$$function__1_greet)) {
    Py_XDECREF(cache_frame_frame___main__$$$function__1_greet);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame___main__$$$function__1_greet == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame___main__$$$function__1_greet = MAKE_FUNCTION_FRAME(tstate, code_objects_83a2583323fc2cfc712dc6af57219eb8, module___main__, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame___main__$$$function__1_greet->m_type_description == NULL);
frame_frame___main__$$$function__1_greet = cache_frame_frame___main__$$$function__1_greet;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame___main__$$$function__1_greet);
assert(Py_REFCNT(frame_frame___main__$$$function__1_greet) == 2);

// Framed code:
{
PyObject *tmp_string_concat_values_1;
PyObject *tmp_tuple_element_1;
tmp_tuple_element_1 = mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7;
tmp_string_concat_values_1 = MAKE_TUPLE_EMPTY(tstate, 5);
{
PyObject *tmp_format_value_1;
PyObject *tmp_format_spec_1;
PyObject *tmp_format_value_2;
PyObject *tmp_format_spec_2;
PyTuple_SET_ITEM0(tmp_string_concat_values_1, 0, tmp_tuple_element_1);
CHECK_OBJECT(par_name);
tmp_format_value_1 = par_name;
tmp_format_spec_1 = const_str_empty;
tmp_tuple_element_1 = BUILTIN_FORMAT(tstate, tmp_format_value_1, tmp_format_spec_1);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 5;
type_description_1 = "o";
    goto tuple_build_exception_1;
}
PyTuple_SET_ITEM(tmp_string_concat_values_1, 1, tmp_tuple_element_1);
tmp_tuple_element_1 = mod_consts.const_str_digest_ae1bf19510647fb9d159b650e3dcc9f7;
PyTuple_SET_ITEM0(tmp_string_concat_values_1, 2, tmp_tuple_element_1);
tmp_format_value_2 = module_var_accessor___main__$MARKER(tstate);
if (unlikely(tmp_format_value_2 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_MARKER);
}

if (tmp_format_value_2 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 5;
type_description_1 = "o";
    goto tuple_build_exception_1;
}
tmp_format_spec_2 = const_str_empty;
tmp_tuple_element_1 = BUILTIN_FORMAT(tstate, tmp_format_value_2, tmp_format_spec_2);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 5;
type_description_1 = "o";
    goto tuple_build_exception_1;
}
PyTuple_SET_ITEM(tmp_string_concat_values_1, 3, tmp_tuple_element_1);
tmp_tuple_element_1 = mod_consts.const_str_chr_93;
PyTuple_SET_ITEM0(tmp_string_concat_values_1, 4, tmp_tuple_element_1);
}
goto tuple_build_no_exception_1;
// Exception handling pass through code for tuple_build:
tuple_build_exception_1:;
Py_DECREF(tmp_string_concat_values_1);
goto frame_exception_exit_1;
// Finished with no exception for tuple_build:
tuple_build_no_exception_1:;
tmp_return_value = PyUnicode_Join(const_str_empty, tmp_string_concat_values_1);
CHECK_OBJECT(tmp_string_concat_values_1);
Py_DECREF(tmp_string_concat_values_1);
assert(!(tmp_return_value == NULL));
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
        exception_tb = MAKE_TRACEBACK(frame_frame___main__$$$function__1_greet, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame___main__$$$function__1_greet->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame___main__$$$function__1_greet, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame___main__$$$function__1_greet,
    type_description_1,
    par_name
);


// Release cached frame if used for exception.
if (frame_frame___main__$$$function__1_greet == cache_frame_frame___main__$$$function__1_greet) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame___main__$$$function__1_greet);
    cache_frame_frame___main__$$$function__1_greet = NULL;
}

assertFrameObject(frame_frame___main__$$$function__1_greet);

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


static PyObject *impl___main__$$$function__2_fib(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
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
PyObject *tmp_tuple_unpack_2__element_1 = NULL;
PyObject *tmp_tuple_unpack_2__element_2 = NULL;
PyObject *tmp_tuple_unpack_2__source_iter = NULL;
struct Nuitka_FrameObject *frame_frame___main__$$$function__2_fib;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
PyObject *tmp_return_value = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_3;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_3;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_4;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_4;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_5;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_5;
static struct Nuitka_FrameObject *cache_frame_frame___main__$$$function__2_fib = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_6;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_6;

    // Actual function body.
// Tried code:
if (isFrameUnusable(cache_frame_frame___main__$$$function__2_fib)) {
    Py_XDECREF(cache_frame_frame___main__$$$function__2_fib);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame___main__$$$function__2_fib == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame___main__$$$function__2_fib = MAKE_FUNCTION_FRAME(tstate, code_objects_0bb3047bc620f1098daa8345034651f8, module___main__, sizeof(void *)+sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame___main__$$$function__2_fib->m_type_description == NULL);
frame_frame___main__$$$function__2_fib = cache_frame_frame___main__$$$function__2_fib;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame___main__$$$function__2_fib);
assert(Py_REFCNT(frame_frame___main__$$$function__2_fib) == 2);

// Framed code:
{
nuitka_bool tmp_condition_result_1;
PyObject *tmp_cmp_expr_left_1;
PyObject *tmp_cmp_expr_right_1;
CHECK_OBJECT(par_n);
tmp_cmp_expr_left_1 = par_n;
tmp_cmp_expr_right_1 = mod_consts.const_int_pos_2;
tmp_condition_result_1 = RICH_COMPARE_LT_NBOOL_OBJECT_LONG(tmp_cmp_expr_left_1, tmp_cmp_expr_right_1);
if (tmp_condition_result_1 == NUITKA_BOOL_EXCEPTION) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 9;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
if (tmp_condition_result_1 == NUITKA_BOOL_TRUE) {
    goto branch_yes_1;
} else {
    goto branch_no_1;
}
}
branch_yes_1:;
CHECK_OBJECT(par_n);
tmp_return_value = par_n;
Py_INCREF(tmp_return_value);
goto frame_return_exit_1;
branch_no_1:;
{
PyObject *tmp_assign_source_1;
PyObject *tmp_iter_arg_1;
tmp_iter_arg_1 = mod_consts.const_tuple_int_0_int_pos_1_tuple;
tmp_assign_source_1 = MAKE_ITERATOR_INFALLIBLE(tmp_iter_arg_1);
assert(!(tmp_assign_source_1 == NULL));
{
    PyObject *old = tmp_tuple_unpack_1__source_iter;
    tmp_tuple_unpack_1__source_iter = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
// Tried code:
// Tried code:
{
PyObject *tmp_assign_source_2;
PyObject *tmp_unpack_1;
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
tmp_unpack_1 = tmp_tuple_unpack_1__source_iter;
tmp_assign_source_2 = UNPACK_NEXT(tstate, &exception_state, tmp_unpack_1, 0, 2);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 11;
type_description_1 = "oooo";
    goto try_except_handler_3;
}
{
    PyObject *old = tmp_tuple_unpack_1__element_1;
    tmp_tuple_unpack_1__element_1 = tmp_assign_source_2;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_3;
PyObject *tmp_unpack_2;
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
tmp_unpack_2 = tmp_tuple_unpack_1__source_iter;
tmp_assign_source_3 = UNPACK_NEXT(tstate, &exception_state, tmp_unpack_2, 1, 2);
if (tmp_assign_source_3 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 11;
type_description_1 = "oooo";
    goto try_except_handler_3;
}
{
    PyObject *old = tmp_tuple_unpack_1__element_2;
    tmp_tuple_unpack_1__element_2 = tmp_assign_source_3;
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



exception_lineno = 11;
type_description_1 = "oooo";
    goto try_except_handler_3;
}
}
goto try_end_1;
// Exception handler code:
try_except_handler_3:;
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

goto try_except_handler_2;
// End of try:
try_end_1:;
goto try_end_2;
// Exception handler code:
try_except_handler_2:;
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

goto frame_exception_exit_1;
// End of try:
try_end_2:;
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
Py_DECREF(tmp_tuple_unpack_1__source_iter);
tmp_tuple_unpack_1__source_iter = NULL;
{
PyObject *tmp_assign_source_4;
CHECK_OBJECT(tmp_tuple_unpack_1__element_1);
tmp_assign_source_4 = tmp_tuple_unpack_1__element_1;
{
    PyObject *old = var_a;
    var_a = tmp_assign_source_4;
    Py_INCREF(var_a);
    Py_XDECREF(old);
}

}
Py_XDECREF(tmp_tuple_unpack_1__element_1);
tmp_tuple_unpack_1__element_1 = NULL;

{
PyObject *tmp_assign_source_5;
CHECK_OBJECT(tmp_tuple_unpack_1__element_2);
tmp_assign_source_5 = tmp_tuple_unpack_1__element_2;
{
    PyObject *old = var_b;
    var_b = tmp_assign_source_5;
    Py_INCREF(var_b);
    Py_XDECREF(old);
}

}
Py_XDECREF(tmp_tuple_unpack_1__element_2);
tmp_tuple_unpack_1__element_2 = NULL;

{
PyObject *tmp_assign_source_6;
PyObject *tmp_iter_arg_2;
PyObject *tmp_xrange_low_1;
PyObject *tmp_sub_expr_left_1;
PyObject *tmp_sub_expr_right_1;
CHECK_OBJECT(par_n);
tmp_sub_expr_left_1 = par_n;
tmp_sub_expr_right_1 = const_int_pos_1;
tmp_xrange_low_1 = BINARY_OPERATION_SUB_OBJECT_OBJECT_LONG(tmp_sub_expr_left_1, tmp_sub_expr_right_1);
if (tmp_xrange_low_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 12;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
tmp_iter_arg_2 = BUILTIN_XRANGE1(tstate, tmp_xrange_low_1);
CHECK_OBJECT(tmp_xrange_low_1);
Py_DECREF(tmp_xrange_low_1);
if (tmp_iter_arg_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 12;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
tmp_assign_source_6 = MAKE_ITERATOR(tstate, tmp_iter_arg_2);
CHECK_OBJECT(tmp_iter_arg_2);
Py_DECREF(tmp_iter_arg_2);
if (tmp_assign_source_6 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 12;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = tmp_for_loop_1__for_iterator;
    tmp_for_loop_1__for_iterator = tmp_assign_source_6;
    Py_XDECREF(old);
}

}
// Tried code:
loop_start_1:;
{
PyObject *tmp_next_source_1;
PyObject *tmp_assign_source_7;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
tmp_next_source_1 = tmp_for_loop_1__for_iterator;
tmp_assign_source_7 = ITERATOR_NEXT_ITERATOR(tmp_next_source_1);
if (tmp_assign_source_7 == NULL) {
    if (CHECK_AND_CLEAR_STOP_ITERATION_OCCURRED(tstate)) {

        goto loop_end_1;
    } else {

        FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
type_description_1 = "oooo";
exception_lineno = 12;
        goto try_except_handler_4;
    }
}

{
    PyObject *old = tmp_for_loop_1__iter_value;
    tmp_for_loop_1__iter_value = tmp_assign_source_7;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_8;
CHECK_OBJECT(tmp_for_loop_1__iter_value);
tmp_assign_source_8 = tmp_for_loop_1__iter_value;
{
    PyObject *old = var__;
    var__ = tmp_assign_source_8;
    Py_INCREF(var__);
    Py_XDECREF(old);
}

}
// Tried code:
{
PyObject *tmp_assign_source_9;
PyObject *tmp_iter_arg_3;
PyObject *tmp_tuple_element_1;
if (var_b == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, const_str_plain_b);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 13;
type_description_1 = "oooo";
    goto try_except_handler_5;
}

tmp_tuple_element_1 = var_b;
tmp_iter_arg_3 = MAKE_TUPLE_EMPTY(tstate, 2);
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
PyTuple_SET_ITEM0(tmp_iter_arg_3, 0, tmp_tuple_element_1);
if (var_a == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, mod_consts.const_str_plain_a);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 13;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}

tmp_add_expr_left_1 = var_a;
if (var_b == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, const_str_plain_b);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 13;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}

tmp_add_expr_right_1 = var_b;
tmp_tuple_element_1 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 13;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}
PyTuple_SET_ITEM(tmp_iter_arg_3, 1, tmp_tuple_element_1);
}
goto tuple_build_no_exception_1;
// Exception handling pass through code for tuple_build:
tuple_build_exception_1:;
Py_DECREF(tmp_iter_arg_3);
goto try_except_handler_5;
// Finished with no exception for tuple_build:
tuple_build_no_exception_1:;
tmp_assign_source_9 = MAKE_ITERATOR_INFALLIBLE(tmp_iter_arg_3);
CHECK_OBJECT(tmp_iter_arg_3);
Py_DECREF(tmp_iter_arg_3);
assert(!(tmp_assign_source_9 == NULL));
{
    PyObject *old = tmp_tuple_unpack_2__source_iter;
    tmp_tuple_unpack_2__source_iter = tmp_assign_source_9;
    Py_XDECREF(old);
}

}
// Tried code:
{
PyObject *tmp_assign_source_10;
PyObject *tmp_unpack_3;
CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
tmp_unpack_3 = tmp_tuple_unpack_2__source_iter;
tmp_assign_source_10 = UNPACK_NEXT(tstate, &exception_state, tmp_unpack_3, 0, 2);
if (tmp_assign_source_10 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 13;
type_description_1 = "oooo";
    goto try_except_handler_6;
}
{
    PyObject *old = tmp_tuple_unpack_2__element_1;
    tmp_tuple_unpack_2__element_1 = tmp_assign_source_10;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_11;
PyObject *tmp_unpack_4;
CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
tmp_unpack_4 = tmp_tuple_unpack_2__source_iter;
tmp_assign_source_11 = UNPACK_NEXT(tstate, &exception_state, tmp_unpack_4, 1, 2);
if (tmp_assign_source_11 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 13;
type_description_1 = "oooo";
    goto try_except_handler_6;
}
{
    PyObject *old = tmp_tuple_unpack_2__element_2;
    tmp_tuple_unpack_2__element_2 = tmp_assign_source_11;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_iterator_name_2;
CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
tmp_iterator_name_2 = tmp_tuple_unpack_2__source_iter;
tmp_result = UNPACK_ITERATOR_CHECK(tstate, &exception_state, tmp_iterator_name_2, 2);
if (tmp_result == false) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 13;
type_description_1 = "oooo";
    goto try_except_handler_6;
}
}
goto try_end_3;
// Exception handler code:
try_except_handler_6:;
exception_keeper_lineno_3 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_3 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
Py_DECREF(tmp_tuple_unpack_2__source_iter);
tmp_tuple_unpack_2__source_iter = NULL;
// Re-raise.
exception_state = exception_keeper_name_3;
exception_lineno = exception_keeper_lineno_3;

goto try_except_handler_5;
// End of try:
try_end_3:;
goto try_end_4;
// Exception handler code:
try_except_handler_5:;
exception_keeper_lineno_4 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_4 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_tuple_unpack_2__element_1);
tmp_tuple_unpack_2__element_1 = NULL;
Py_XDECREF(tmp_tuple_unpack_2__element_2);
tmp_tuple_unpack_2__element_2 = NULL;
// Re-raise.
exception_state = exception_keeper_name_4;
exception_lineno = exception_keeper_lineno_4;

goto try_except_handler_4;
// End of try:
try_end_4:;
CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
Py_DECREF(tmp_tuple_unpack_2__source_iter);
tmp_tuple_unpack_2__source_iter = NULL;
{
PyObject *tmp_assign_source_12;
CHECK_OBJECT(tmp_tuple_unpack_2__element_1);
tmp_assign_source_12 = tmp_tuple_unpack_2__element_1;
{
    PyObject *old = var_a;
    var_a = tmp_assign_source_12;
    Py_INCREF(var_a);
    Py_XDECREF(old);
}

}
Py_XDECREF(tmp_tuple_unpack_2__element_1);
tmp_tuple_unpack_2__element_1 = NULL;

{
PyObject *tmp_assign_source_13;
CHECK_OBJECT(tmp_tuple_unpack_2__element_2);
tmp_assign_source_13 = tmp_tuple_unpack_2__element_2;
{
    PyObject *old = var_b;
    var_b = tmp_assign_source_13;
    Py_INCREF(var_b);
    Py_XDECREF(old);
}

}
Py_XDECREF(tmp_tuple_unpack_2__element_2);
tmp_tuple_unpack_2__element_2 = NULL;

if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 12;
type_description_1 = "oooo";
    goto try_except_handler_4;
}
goto loop_start_1;
loop_end_1:;
goto try_end_5;
// Exception handler code:
try_except_handler_4:;
exception_keeper_lineno_5 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_5 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_for_loop_1__iter_value);
tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
Py_DECREF(tmp_for_loop_1__for_iterator);
tmp_for_loop_1__for_iterator = NULL;
// Re-raise.
exception_state = exception_keeper_name_5;
exception_lineno = exception_keeper_lineno_5;

goto frame_exception_exit_1;
// End of try:
try_end_5:;
Py_XDECREF(tmp_for_loop_1__iter_value);
tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
CHECK_OBJECT(tmp_for_loop_1__for_iterator);
Py_DECREF(tmp_for_loop_1__for_iterator);
tmp_for_loop_1__for_iterator = NULL;
if (var_b == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, const_str_plain_b);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 14;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}

tmp_return_value = var_b;
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
        exception_tb = MAKE_TRACEBACK(frame_frame___main__$$$function__2_fib, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame___main__$$$function__2_fib->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame___main__$$$function__2_fib, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame___main__$$$function__2_fib,
    type_description_1,
    par_n,
    var_a,
    var_b,
    var__
);


// Release cached frame if used for exception.
if (frame_frame___main__$$$function__2_fib == cache_frame_frame___main__$$$function__2_fib) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame___main__$$$function__2_fib);
    cache_frame_frame___main__$$$function__2_fib = NULL;
}

assertFrameObject(frame_frame___main__$$$function__2_fib);

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
exception_keeper_lineno_6 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_6 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_a);
var_a = NULL;
Py_XDECREF(var_b);
var_b = NULL;
Py_XDECREF(var__);
var__ = NULL;
// Re-raise.
exception_state = exception_keeper_name_6;
exception_lineno = exception_keeper_lineno_6;

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


static PyObject *impl___main__$$$function__3_main(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
struct Nuitka_FrameObject *frame_frame___main__$$$function__3_main;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
NUITKA_MAY_BE_UNUSED nuitka_void tmp_unused;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame___main__$$$function__3_main = NULL;
PyObject *tmp_return_value = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame___main__$$$function__3_main)) {
    Py_XDECREF(cache_frame_frame___main__$$$function__3_main);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame___main__$$$function__3_main == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame___main__$$$function__3_main = MAKE_FUNCTION_FRAME(tstate, code_objects_31194cfd0811358daf03c7129c3e07b7, module___main__, 0);
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame___main__$$$function__3_main->m_type_description == NULL);
frame_frame___main__$$$function__3_main = cache_frame_frame___main__$$$function__3_main;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame___main__$$$function__3_main);
assert(Py_REFCNT(frame_frame___main__$$$function__3_main) == 2);

// Framed code:
{
PyObject *tmp_called_value_1;
PyObject *tmp_call_result_1;
PyObject *tmp_args_element_value_1;
PyObject *tmp_called_value_2;
tmp_called_value_1 = LOOKUP_BUILTIN(const_str_plain_print);
assert(tmp_called_value_1 != NULL);
tmp_called_value_2 = module_var_accessor___main__$greet(tstate);
if (unlikely(tmp_called_value_2 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_greet);
}

if (tmp_called_value_2 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 18;

    goto frame_exception_exit_1;
}
frame_frame___main__$$$function__3_main->m_frame.f_lineno = 18;
tmp_args_element_value_1 = CALL_FUNCTION_WITH_POS_ARGS1(tstate, tmp_called_value_2, mod_consts.const_tuple_str_plain_disrobe_tuple);

if (tmp_args_element_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 18;

    goto frame_exception_exit_1;
}
frame_frame___main__$$$function__3_main->m_frame.f_lineno = 18;
tmp_call_result_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_1, tmp_args_element_value_1);
CHECK_OBJECT(tmp_args_element_value_1);
Py_DECREF(tmp_args_element_value_1);
if (tmp_call_result_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 18;

    goto frame_exception_exit_1;
}
CHECK_OBJECT(tmp_call_result_1);
Py_DECREF(tmp_call_result_1);
}
{
PyObject *tmp_called_value_3;
PyObject *tmp_call_result_2;
PyObject *tmp_args_element_value_2;
PyObject *tmp_called_value_4;
tmp_called_value_3 = LOOKUP_BUILTIN(const_str_plain_print);
assert(tmp_called_value_3 != NULL);
tmp_called_value_4 = module_var_accessor___main__$fib(tstate);
if (unlikely(tmp_called_value_4 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_fib);
}

if (tmp_called_value_4 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 19;

    goto frame_exception_exit_1;
}
frame_frame___main__$$$function__3_main->m_frame.f_lineno = 19;
tmp_args_element_value_2 = CALL_FUNCTION_WITH_POS_ARGS1(tstate, tmp_called_value_4, mod_consts.const_tuple_int_pos_20_tuple);

if (tmp_args_element_value_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 19;

    goto frame_exception_exit_1;
}
frame_frame___main__$$$function__3_main->m_frame.f_lineno = 19;
tmp_call_result_2 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_3, tmp_args_element_value_2);
CHECK_OBJECT(tmp_args_element_value_2);
Py_DECREF(tmp_args_element_value_2);
if (tmp_call_result_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 19;

    goto frame_exception_exit_1;
}
CHECK_OBJECT(tmp_call_result_2);
Py_DECREF(tmp_call_result_2);
}


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame___main__$$$function__3_main, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame___main__$$$function__3_main->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame___main__$$$function__3_main, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame___main__$$$function__3_main,
    type_description_1
);


// Release cached frame if used for exception.
if (frame_frame___main__$$$function__3_main == cache_frame_frame___main__$$$function__3_main) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame___main__$$$function__3_main);
    cache_frame_frame___main__$$$function__3_main = NULL;
}

assertFrameObject(frame_frame___main__$$$function__3_main);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;
tmp_return_value = const_int_0;
Py_INCREF_IMMORTAL(tmp_return_value);
goto function_return_exit;

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



static PyObject *MAKE_FUNCTION___main__$$$function__1_greet(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl___main__$$$function__1_greet,
        mod_consts.const_str_plain_greet,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_83a2583323fc2cfc712dc6af57219eb8,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module___main__,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION___main__$$$function__2_fib(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl___main__$$$function__2_fib,
        mod_consts.const_str_plain_fib,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_0bb3047bc620f1098daa8345034651f8,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module___main__,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION___main__$$$function__3_main(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl___main__$$$function__3_main,
        mod_consts.const_str_plain_main,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_31194cfd0811358daf03c7129c3e07b7,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module___main__,
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

static function_impl_code const function_table___main__[] = {
impl___main__$$$function__1_greet,
impl___main__$$$function__2_fib,
impl___main__$$$function__3_main,
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

    return Nuitka_Function_GetFunctionState(function, function_table___main__);
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
        module___main__,
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
        function_table___main__,
        sizeof(function_table___main__) / sizeof(function_impl_code)
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
static char const *module_full_name = "__main__";
#endif

// Internal entry point for module code.
PyObject *module_code___main__(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("__main__");

    // Store the module for future use.
    module___main__ = module;

    moduledict___main__ = MODULE_DICT(module___main__);

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
        PRINT_STRING("__main__: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("__main__: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("__main__: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "__main__" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in init__main__\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict___main__,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 1
        UPDATE_STRING_DICT0(
            moduledict___main__,
            (Nuitka_StringObject *)const_str_plain___package__,
            Py_None
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict___main__,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict___main__,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict___main__,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module___main__);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !1
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict___main__, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict___main__, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 1
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict___main__, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module___main__);
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

        UPDATE_STRING_DICT1(moduledict___main__, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame___main__;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
NUITKA_MAY_BE_UNUSED nuitka_void tmp_unused;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
frame_frame___main__ = MAKE_MODULE_FRAME(code_objects_36c4fffdf4652f37ce17487e09cbaccb, module___main__);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame___main__);
assert(Py_REFCNT(frame_frame___main__) == 2);

// Framed code:
{
PyObject *tmp_imported_value_1;
frame_frame___main__->m_frame.f_lineno = 1;
tmp_imported_value_1 = IMPORT_HARD_SITE();
if (tmp_imported_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto frame_exception_exit_1;
}
}
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict___main__, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = mod_consts.const_str_digest_aa6b8c53800e7e7accecdd8ee93229d0;
UPDATE_STRING_DICT0(moduledict___main__, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict___main__, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict___main__, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
tmp_assign_source_5 = mod_consts.const_str_plain_DISROBE_NUITKA_FIXTURE_MARKER_8f3a1c;
UPDATE_STRING_DICT0(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_MARKER, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
PyObject *tmp_annotations_1;
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3);

tmp_assign_source_6 = MAKE_FUNCTION___main__$$$function__1_greet(tstate, tmp_annotations_1);

UPDATE_STRING_DICT1(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_greet, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;
PyObject *tmp_annotations_2;
tmp_annotations_2 = DICT_COPY(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);

tmp_assign_source_7 = MAKE_FUNCTION___main__$$$function__2_fib(tstate, tmp_annotations_2);

UPDATE_STRING_DICT1(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_fib, tmp_assign_source_7);
}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_annotations_3;
tmp_annotations_3 = DICT_COPY(tstate, mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617);

tmp_assign_source_8 = MAKE_FUNCTION___main__$$$function__3_main(tstate, tmp_annotations_3);

UPDATE_STRING_DICT1(moduledict___main__, (Nuitka_StringObject *)mod_consts.const_str_plain_main, tmp_assign_source_8);
}
{
PyObject *tmp_raise_type_1;
PyObject *tmp_make_exception_arg_1;
PyObject *tmp_called_value_1;
tmp_called_value_1 = module_var_accessor___main__$main(tstate);
assert(!(tmp_called_value_1 == NULL));
frame_frame___main__->m_frame.f_lineno = 24;
tmp_make_exception_arg_1 = CALL_FUNCTION_NO_ARGS(tstate, tmp_called_value_1);
if (tmp_make_exception_arg_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 24;

    goto frame_exception_exit_1;
}
frame_frame___main__->m_frame.f_lineno = 24;
tmp_raise_type_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, PyExc_SystemExit, tmp_make_exception_arg_1);
CHECK_OBJECT(tmp_make_exception_arg_1);
Py_DECREF(tmp_make_exception_arg_1);
assert(!(tmp_raise_type_1 == NULL));
exception_state.exception_value = tmp_raise_type_1;
exception_lineno = 24;
RAISE_EXCEPTION_WITH_VALUE(tstate, &exception_state);

goto frame_exception_exit_1;
}


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame___main__, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame___main__->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame___main__, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame___main__);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("__main__", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "__main__" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module___main__);
    return module___main__;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict___main__, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("__main__", false);

    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);
    return NULL;
}
