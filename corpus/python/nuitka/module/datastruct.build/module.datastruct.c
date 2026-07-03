/* Generated code for Python module 'datastruct'
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



/* The "module_datastruct" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_datastruct;
PyDictObject *moduledict_datastruct;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_dict_ab4b8895c76990ee22ef1eb646200841;
PyObject *const_str_plain_make_pair;
PyObject *const_dict_31e68efd53cbc16164a8ef71d623a7e3;
PyObject *const_str_plain_make_dict;
PyObject *const_dict_931d4e41440e5948c9eaaba647e23bf6;
PyObject *const_str_plain_first;
PyObject *const_str_plain_pair_sum;
PyObject *const_dict_13b9992d5bea1b1702711b17dbcebe8e;
PyObject *const_str_plain_boolop;
PyObject *const_dict_ac2d17ccf098d71f8de0232b23b5a904;
PyObject *const_str_plain_ternary;
PyObject *const_str_digest_68af089679d730e4c21aa432bf5bb7d6;
PyObject *const_str_digest_76ee03b0de4eb6f720b0114561f0bf17;
PyObject *const_tuple_str_plain_a_str_plain_b_tuple;
PyObject *const_tuple_str_plain_items_tuple;
PyObject *const_tuple_str_plain_k_str_plain_v_tuple;
PyObject *const_tuple_str_plain_n_tuple;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[19];
#endif

static PyObject *module_filename_obj = NULL;

/* Indicator if this modules private constants were created yet. */
static bool constants_created = false;

/* Function to create module private constants. */
static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("datastruct"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 19) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 19 values, got %d\n",
                    UN_TRANSLATE("datastruct"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ab4b8895c76990ee22ef1eb646200841", mod_consts.const_dict_ab4b8895c76990ee22ef1eb646200841);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_dict_ab4b8895c76990ee22ef1eb646200841);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_make_pair", mod_consts.const_str_plain_make_pair);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_plain_make_pair);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_31e68efd53cbc16164a8ef71d623a7e3", mod_consts.const_dict_31e68efd53cbc16164a8ef71d623a7e3);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_dict_31e68efd53cbc16164a8ef71d623a7e3);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_make_dict", mod_consts.const_str_plain_make_dict);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_str_plain_make_dict);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6", mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_first", mod_consts.const_str_plain_first);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_str_plain_first);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_pair_sum", mod_consts.const_str_plain_pair_sum);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_str_plain_pair_sum);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_13b9992d5bea1b1702711b17dbcebe8e", mod_consts.const_dict_13b9992d5bea1b1702711b17dbcebe8e);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_dict_13b9992d5bea1b1702711b17dbcebe8e);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_boolop", mod_consts.const_str_plain_boolop);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_str_plain_boolop);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_ternary", mod_consts.const_str_plain_ternary);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_str_plain_ternary);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_68af089679d730e4c21aa432bf5bb7d6", mod_consts.const_str_digest_68af089679d730e4c21aa432bf5bb7d6);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_str_digest_68af089679d730e4c21aa432bf5bb7d6);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17", mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_items_tuple", mod_consts.const_tuple_str_plain_items_tuple);
mod_consts_hash[16] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_items_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_k_str_plain_v_tuple", mod_consts.const_tuple_str_plain_k_str_plain_v_tuple);
mod_consts_hash[17] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_k_str_plain_v_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
mod_consts_hash[18] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple);
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
void checkModuleConstants_datastruct(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ab4b8895c76990ee22ef1eb646200841", mod_consts.const_dict_ab4b8895c76990ee22ef1eb646200841);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_dict_ab4b8895c76990ee22ef1eb646200841) && "mod_consts.const_dict_ab4b8895c76990ee22ef1eb646200841");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_make_pair", mod_consts.const_str_plain_make_pair);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_plain_make_pair) && "mod_consts.const_str_plain_make_pair");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_31e68efd53cbc16164a8ef71d623a7e3", mod_consts.const_dict_31e68efd53cbc16164a8ef71d623a7e3);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_dict_31e68efd53cbc16164a8ef71d623a7e3) && "mod_consts.const_dict_31e68efd53cbc16164a8ef71d623a7e3");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_make_dict", mod_consts.const_str_plain_make_dict);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_str_plain_make_dict) && "mod_consts.const_str_plain_make_dict");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6", mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6) && "mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_first", mod_consts.const_str_plain_first);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_str_plain_first) && "mod_consts.const_str_plain_first");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_pair_sum", mod_consts.const_str_plain_pair_sum);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_str_plain_pair_sum) && "mod_consts.const_str_plain_pair_sum");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_13b9992d5bea1b1702711b17dbcebe8e", mod_consts.const_dict_13b9992d5bea1b1702711b17dbcebe8e);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_dict_13b9992d5bea1b1702711b17dbcebe8e) && "mod_consts.const_dict_13b9992d5bea1b1702711b17dbcebe8e");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_boolop", mod_consts.const_str_plain_boolop);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_str_plain_boolop) && "mod_consts.const_str_plain_boolop");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904) && "mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_ternary", mod_consts.const_str_plain_ternary);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_str_plain_ternary) && "mod_consts.const_str_plain_ternary");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_68af089679d730e4c21aa432bf5bb7d6", mod_consts.const_str_digest_68af089679d730e4c21aa432bf5bb7d6);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_str_digest_68af089679d730e4c21aa432bf5bb7d6) && "mod_consts.const_str_digest_68af089679d730e4c21aa432bf5bb7d6");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17", mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17) && "mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple) && "mod_consts.const_tuple_str_plain_a_str_plain_b_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_items_tuple", mod_consts.const_tuple_str_plain_items_tuple);
assert(mod_consts_hash[16] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_items_tuple) && "mod_consts.const_tuple_str_plain_items_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_k_str_plain_v_tuple", mod_consts.const_tuple_str_plain_k_str_plain_v_tuple);
assert(mod_consts_hash[17] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_k_str_plain_v_tuple) && "mod_consts.const_tuple_str_plain_k_str_plain_v_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
assert(mod_consts_hash[18] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple) && "mod_consts.const_tuple_str_plain_n_tuple");
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
static PyObject *module_var_accessor_datastruct$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_datastruct->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_datastruct->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_datastruct->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_045dbedb978ff91dfde6c7f9e75e7efe;
static PyCodeObject *code_objects_944fdf1f5de1965ed9e6ba25624553f3;
static PyCodeObject *code_objects_e51f6a7d130297f7452a273ad0aabd43;
static PyCodeObject *code_objects_19c7f5b60f9221bde14f5133c67d155f;
static PyCodeObject *code_objects_c145fe162de9de66937d4895ccd77cdc;
static PyCodeObject *code_objects_44a2c9eec8cb42e13dca18ec6a207c75;
static PyCodeObject *code_objects_01ec61f98bbb46ea7f1ac4790fc8a7b0;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_68af089679d730e4c21aa432bf5bb7d6); CHECK_OBJECT(module_filename_obj);
code_objects_045dbedb978ff91dfde6c7f9e75e7efe = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17, mod_consts.const_str_digest_76ee03b0de4eb6f720b0114561f0bf17, NULL, NULL, 0, 0, 0);
code_objects_944fdf1f5de1965ed9e6ba25624553f3 = MAKE_CODE_OBJECT(module_filename_obj, 17, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_boolop, mod_consts.const_str_plain_boolop, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple, NULL, 2, 0, 0);
code_objects_e51f6a7d130297f7452a273ad0aabd43 = MAKE_CODE_OBJECT(module_filename_obj, 9, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_first, mod_consts.const_str_plain_first, mod_consts.const_tuple_str_plain_items_tuple, NULL, 1, 0, 0);
code_objects_19c7f5b60f9221bde14f5133c67d155f = MAKE_CODE_OBJECT(module_filename_obj, 5, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_make_dict, mod_consts.const_str_plain_make_dict, mod_consts.const_tuple_str_plain_k_str_plain_v_tuple, NULL, 2, 0, 0);
code_objects_c145fe162de9de66937d4895ccd77cdc = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_make_pair, mod_consts.const_str_plain_make_pair, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple, NULL, 2, 0, 0);
code_objects_44a2c9eec8cb42e13dca18ec6a207c75 = MAKE_CODE_OBJECT(module_filename_obj, 13, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_pair_sum, mod_consts.const_str_plain_pair_sum, mod_consts.const_tuple_str_plain_items_tuple, NULL, 1, 0, 0);
code_objects_01ec61f98bbb46ea7f1ac4790fc8a7b0 = MAKE_CODE_OBJECT(module_filename_obj, 21, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_ternary, mod_consts.const_str_plain_ternary, mod_consts.const_tuple_str_plain_n_tuple, NULL, 1, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION_datastruct$$$function__1_make_pair(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_datastruct$$$function__2_make_dict(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_datastruct$$$function__3_first(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_datastruct$$$function__4_pair_sum(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_datastruct$$$function__5_boolop(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_datastruct$$$function__6_ternary(PyThreadState *tstate, PyObject *annotations);


// The module function definitions.
static PyObject *impl_datastruct$$$function__1_make_pair(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
PyObject *tmp_return_value = NULL;

    // Actual function body.
{
PyObject *tmp_list_element_1;
CHECK_OBJECT(par_a);
tmp_list_element_1 = par_a;
tmp_return_value = MAKE_LIST_EMPTY(tstate, 2);
PyList_SET_ITEM0(tmp_return_value, 0, tmp_list_element_1);
CHECK_OBJECT(par_b);
tmp_list_element_1 = par_b;
PyList_SET_ITEM0(tmp_return_value, 1, tmp_list_element_1);
goto function_return_exit;
}

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
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


static PyObject *impl_datastruct$$$function__2_make_dict(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_k = python_pars[0];
PyObject *par_v = python_pars[1];
struct Nuitka_FrameObject *frame_frame_datastruct$$$function__2_make_dict;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
int tmp_res;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_datastruct$$$function__2_make_dict = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_datastruct$$$function__2_make_dict)) {
    Py_XDECREF(cache_frame_frame_datastruct$$$function__2_make_dict);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_datastruct$$$function__2_make_dict == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_datastruct$$$function__2_make_dict = MAKE_FUNCTION_FRAME(tstate, code_objects_19c7f5b60f9221bde14f5133c67d155f, module_datastruct, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_datastruct$$$function__2_make_dict->m_type_description == NULL);
frame_frame_datastruct$$$function__2_make_dict = cache_frame_frame_datastruct$$$function__2_make_dict;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_datastruct$$$function__2_make_dict);
assert(Py_REFCNT(frame_frame_datastruct$$$function__2_make_dict) == 2);

// Framed code:
{
PyObject *tmp_dict_key_1;
PyObject *tmp_dict_value_1;
CHECK_OBJECT(par_k);
tmp_dict_key_1 = par_k;
CHECK_OBJECT(par_v);
tmp_dict_value_1 = par_v;
tmp_return_value = _PyDict_NewPresized( 1 );
tmp_res = PyDict_SetItem(tmp_return_value, tmp_dict_key_1, tmp_dict_value_1);
if (tmp_res != 0) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 6;
type_description_1 = "oo";
    goto dict_build_exception_1;
}
goto dict_build_no_exception_1;
// Exception handling pass through code for dict_build:
dict_build_exception_1:;
Py_DECREF(tmp_return_value);
goto frame_exception_exit_1;
// Finished with no exception for dict_build:
dict_build_no_exception_1:;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_datastruct$$$function__2_make_dict, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_datastruct$$$function__2_make_dict->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_datastruct$$$function__2_make_dict, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_datastruct$$$function__2_make_dict,
    type_description_1,
    par_k,
    par_v
);


// Release cached frame if used for exception.
if (frame_frame_datastruct$$$function__2_make_dict == cache_frame_frame_datastruct$$$function__2_make_dict) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_datastruct$$$function__2_make_dict);
    cache_frame_frame_datastruct$$$function__2_make_dict = NULL;
}

assertFrameObject(frame_frame_datastruct$$$function__2_make_dict);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_k);
Py_DECREF(par_k);
CHECK_OBJECT(par_v);
Py_DECREF(par_v);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_k);
Py_DECREF(par_k);
CHECK_OBJECT(par_v);
Py_DECREF(par_v);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_datastruct$$$function__3_first(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_items = python_pars[0];
struct Nuitka_FrameObject *frame_frame_datastruct$$$function__3_first;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_datastruct$$$function__3_first = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_datastruct$$$function__3_first)) {
    Py_XDECREF(cache_frame_frame_datastruct$$$function__3_first);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_datastruct$$$function__3_first == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_datastruct$$$function__3_first = MAKE_FUNCTION_FRAME(tstate, code_objects_e51f6a7d130297f7452a273ad0aabd43, module_datastruct, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_datastruct$$$function__3_first->m_type_description == NULL);
frame_frame_datastruct$$$function__3_first = cache_frame_frame_datastruct$$$function__3_first;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_datastruct$$$function__3_first);
assert(Py_REFCNT(frame_frame_datastruct$$$function__3_first) == 2);

// Framed code:
{
PyObject *tmp_expression_value_1;
PyObject *tmp_subscript_value_1;
CHECK_OBJECT(par_items);
tmp_expression_value_1 = par_items;
tmp_subscript_value_1 = const_int_0;
tmp_return_value = LOOKUP_SUBSCRIPT_CONST(tstate, tmp_expression_value_1, tmp_subscript_value_1, 0);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 10;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_datastruct$$$function__3_first, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_datastruct$$$function__3_first->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_datastruct$$$function__3_first, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_datastruct$$$function__3_first,
    type_description_1,
    par_items
);


// Release cached frame if used for exception.
if (frame_frame_datastruct$$$function__3_first == cache_frame_frame_datastruct$$$function__3_first) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_datastruct$$$function__3_first);
    cache_frame_frame_datastruct$$$function__3_first = NULL;
}

assertFrameObject(frame_frame_datastruct$$$function__3_first);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_items);
Py_DECREF(par_items);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_items);
Py_DECREF(par_items);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_datastruct$$$function__4_pair_sum(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_items = python_pars[0];
struct Nuitka_FrameObject *frame_frame_datastruct$$$function__4_pair_sum;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_datastruct$$$function__4_pair_sum = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_datastruct$$$function__4_pair_sum)) {
    Py_XDECREF(cache_frame_frame_datastruct$$$function__4_pair_sum);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_datastruct$$$function__4_pair_sum == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_datastruct$$$function__4_pair_sum = MAKE_FUNCTION_FRAME(tstate, code_objects_44a2c9eec8cb42e13dca18ec6a207c75, module_datastruct, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_datastruct$$$function__4_pair_sum->m_type_description == NULL);
frame_frame_datastruct$$$function__4_pair_sum = cache_frame_frame_datastruct$$$function__4_pair_sum;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_datastruct$$$function__4_pair_sum);
assert(Py_REFCNT(frame_frame_datastruct$$$function__4_pair_sum) == 2);

// Framed code:
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
PyObject *tmp_expression_value_1;
PyObject *tmp_subscript_value_1;
PyObject *tmp_expression_value_2;
PyObject *tmp_subscript_value_2;
CHECK_OBJECT(par_items);
tmp_expression_value_1 = par_items;
tmp_subscript_value_1 = const_int_0;
tmp_add_expr_left_1 = LOOKUP_SUBSCRIPT_CONST(tstate, tmp_expression_value_1, tmp_subscript_value_1, 0);
if (tmp_add_expr_left_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 14;
type_description_1 = "o";
    goto frame_exception_exit_1;
}
CHECK_OBJECT(par_items);
tmp_expression_value_2 = par_items;
tmp_subscript_value_2 = const_int_pos_1;
tmp_add_expr_right_1 = LOOKUP_SUBSCRIPT_CONST(tstate, tmp_expression_value_2, tmp_subscript_value_2, 1);
if (tmp_add_expr_right_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
Py_DECREF(tmp_add_expr_left_1);

exception_lineno = 14;
type_description_1 = "o";
    goto frame_exception_exit_1;
}
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
CHECK_OBJECT(tmp_add_expr_left_1);
Py_DECREF(tmp_add_expr_left_1);
CHECK_OBJECT(tmp_add_expr_right_1);
Py_DECREF(tmp_add_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 14;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_datastruct$$$function__4_pair_sum, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_datastruct$$$function__4_pair_sum->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_datastruct$$$function__4_pair_sum, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_datastruct$$$function__4_pair_sum,
    type_description_1,
    par_items
);


// Release cached frame if used for exception.
if (frame_frame_datastruct$$$function__4_pair_sum == cache_frame_frame_datastruct$$$function__4_pair_sum) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_datastruct$$$function__4_pair_sum);
    cache_frame_frame_datastruct$$$function__4_pair_sum = NULL;
}

assertFrameObject(frame_frame_datastruct$$$function__4_pair_sum);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_items);
Py_DECREF(par_items);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_items);
Py_DECREF(par_items);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_datastruct$$$function__5_boolop(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
struct Nuitka_FrameObject *frame_frame_datastruct$$$function__5_boolop;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_datastruct$$$function__5_boolop = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_datastruct$$$function__5_boolop)) {
    Py_XDECREF(cache_frame_frame_datastruct$$$function__5_boolop);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_datastruct$$$function__5_boolop == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_datastruct$$$function__5_boolop = MAKE_FUNCTION_FRAME(tstate, code_objects_944fdf1f5de1965ed9e6ba25624553f3, module_datastruct, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_datastruct$$$function__5_boolop->m_type_description == NULL);
frame_frame_datastruct$$$function__5_boolop = cache_frame_frame_datastruct$$$function__5_boolop;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_datastruct$$$function__5_boolop);
assert(Py_REFCNT(frame_frame_datastruct$$$function__5_boolop) == 2);

// Framed code:
{
int tmp_and_left_truth_1;
PyObject *tmp_and_left_value_1;
PyObject *tmp_and_right_value_1;
PyObject *tmp_cmp_expr_left_1;
PyObject *tmp_cmp_expr_right_1;
PyObject *tmp_cmp_expr_left_2;
PyObject *tmp_cmp_expr_right_2;
CHECK_OBJECT(par_a);
tmp_cmp_expr_left_1 = par_a;
tmp_cmp_expr_right_1 = const_int_0;
tmp_and_left_value_1 = RICH_COMPARE_GT_OBJECT_OBJECT_LONG(tmp_cmp_expr_left_1, tmp_cmp_expr_right_1);
if (tmp_and_left_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 18;
type_description_1 = "oo";
    goto frame_exception_exit_1;
}
tmp_and_left_truth_1 = CHECK_IF_TRUE(tmp_and_left_value_1);
if (tmp_and_left_truth_1 == -1) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);
Py_DECREF(tmp_and_left_value_1);

exception_lineno = 18;
type_description_1 = "oo";
    goto frame_exception_exit_1;
}
if (tmp_and_left_truth_1 == 1) {
    goto and_right_1;
} else {
    goto and_left_1;
}
and_right_1:;
CHECK_OBJECT(tmp_and_left_value_1);
Py_DECREF(tmp_and_left_value_1);
CHECK_OBJECT(par_b);
tmp_cmp_expr_left_2 = par_b;
tmp_cmp_expr_right_2 = const_int_0;
tmp_and_right_value_1 = RICH_COMPARE_GT_OBJECT_OBJECT_LONG(tmp_cmp_expr_left_2, tmp_cmp_expr_right_2);
if (tmp_and_right_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 18;
type_description_1 = "oo";
    goto frame_exception_exit_1;
}
tmp_return_value = tmp_and_right_value_1;
goto and_end_1;
and_left_1:;
tmp_return_value = tmp_and_left_value_1;
and_end_1:;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_datastruct$$$function__5_boolop, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_datastruct$$$function__5_boolop->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_datastruct$$$function__5_boolop, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_datastruct$$$function__5_boolop,
    type_description_1,
    par_a,
    par_b
);


// Release cached frame if used for exception.
if (frame_frame_datastruct$$$function__5_boolop == cache_frame_frame_datastruct$$$function__5_boolop) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_datastruct$$$function__5_boolop);
    cache_frame_frame_datastruct$$$function__5_boolop = NULL;
}

assertFrameObject(frame_frame_datastruct$$$function__5_boolop);

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


static PyObject *impl_datastruct$$$function__6_ternary(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_n = python_pars[0];
struct Nuitka_FrameObject *frame_frame_datastruct$$$function__6_ternary;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_datastruct$$$function__6_ternary = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_datastruct$$$function__6_ternary)) {
    Py_XDECREF(cache_frame_frame_datastruct$$$function__6_ternary);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_datastruct$$$function__6_ternary == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_datastruct$$$function__6_ternary = MAKE_FUNCTION_FRAME(tstate, code_objects_01ec61f98bbb46ea7f1ac4790fc8a7b0, module_datastruct, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_datastruct$$$function__6_ternary->m_type_description == NULL);
frame_frame_datastruct$$$function__6_ternary = cache_frame_frame_datastruct$$$function__6_ternary;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_datastruct$$$function__6_ternary);
assert(Py_REFCNT(frame_frame_datastruct$$$function__6_ternary) == 2);

// Framed code:
{
nuitka_bool tmp_condition_result_1;
PyObject *tmp_cmp_expr_left_1;
PyObject *tmp_cmp_expr_right_1;
PyObject *tmp_operand_value_1;
CHECK_OBJECT(par_n);
tmp_cmp_expr_left_1 = par_n;
tmp_cmp_expr_right_1 = const_int_0;
tmp_condition_result_1 = RICH_COMPARE_GT_NBOOL_OBJECT_LONG(tmp_cmp_expr_left_1, tmp_cmp_expr_right_1);
if (tmp_condition_result_1 == NUITKA_BOOL_EXCEPTION) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 22;
type_description_1 = "o";
    goto frame_exception_exit_1;
}
if (tmp_condition_result_1 == NUITKA_BOOL_TRUE) {
    goto condexpr_true_1;
} else {
    goto condexpr_false_1;
}
condexpr_true_1:;
CHECK_OBJECT(par_n);
tmp_return_value = par_n;
Py_INCREF(tmp_return_value);
goto condexpr_end_1;
condexpr_false_1:;
CHECK_OBJECT(par_n);
tmp_operand_value_1 = par_n;
tmp_return_value = UNARY_OPERATION(PyNumber_Negative, tmp_operand_value_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 22;
type_description_1 = "o";
    goto frame_exception_exit_1;
}
condexpr_end_1:;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_datastruct$$$function__6_ternary, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_datastruct$$$function__6_ternary->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_datastruct$$$function__6_ternary, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_datastruct$$$function__6_ternary,
    type_description_1,
    par_n
);


// Release cached frame if used for exception.
if (frame_frame_datastruct$$$function__6_ternary == cache_frame_frame_datastruct$$$function__6_ternary) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_datastruct$$$function__6_ternary);
    cache_frame_frame_datastruct$$$function__6_ternary = NULL;
}

assertFrameObject(frame_frame_datastruct$$$function__6_ternary);

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



static PyObject *MAKE_FUNCTION_datastruct$$$function__1_make_pair(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_datastruct$$$function__1_make_pair,
        mod_consts.const_str_plain_make_pair,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_c145fe162de9de66937d4895ccd77cdc,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_datastruct,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_datastruct$$$function__2_make_dict(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_datastruct$$$function__2_make_dict,
        mod_consts.const_str_plain_make_dict,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_19c7f5b60f9221bde14f5133c67d155f,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_datastruct,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_datastruct$$$function__3_first(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_datastruct$$$function__3_first,
        mod_consts.const_str_plain_first,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_e51f6a7d130297f7452a273ad0aabd43,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_datastruct,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_datastruct$$$function__4_pair_sum(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_datastruct$$$function__4_pair_sum,
        mod_consts.const_str_plain_pair_sum,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_44a2c9eec8cb42e13dca18ec6a207c75,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_datastruct,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_datastruct$$$function__5_boolop(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_datastruct$$$function__5_boolop,
        mod_consts.const_str_plain_boolop,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_944fdf1f5de1965ed9e6ba25624553f3,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_datastruct,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_datastruct$$$function__6_ternary(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_datastruct$$$function__6_ternary,
        mod_consts.const_str_plain_ternary,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_01ec61f98bbb46ea7f1ac4790fc8a7b0,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_datastruct,
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

static function_impl_code const function_table_datastruct[] = {
impl_datastruct$$$function__1_make_pair,
impl_datastruct$$$function__2_make_dict,
impl_datastruct$$$function__3_first,
impl_datastruct$$$function__4_pair_sum,
impl_datastruct$$$function__5_boolop,
impl_datastruct$$$function__6_ternary,
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

    return Nuitka_Function_GetFunctionState(function, function_table_datastruct);
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
        module_datastruct,
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
        function_table_datastruct,
        sizeof(function_table_datastruct) / sizeof(function_impl_code)
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
static char const *module_full_name = "datastruct";
#endif

// Internal entry point for module code.
PyObject *module_code_datastruct(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("datastruct");

    // Store the module for future use.
    module_datastruct = module;

    moduledict_datastruct = MODULE_DICT(module_datastruct);

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
        PRINT_STRING("datastruct: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("datastruct: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("datastruct: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "datastruct" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initdatastruct\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict_datastruct,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_datastruct,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_datastruct,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_datastruct,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_datastruct,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_datastruct);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_datastruct);
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

        UPDATE_STRING_DICT1(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_datastruct;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_datastruct = MAKE_MODULE_FRAME(code_objects_045dbedb978ff91dfde6c7f9e75e7efe, module_datastruct);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_datastruct);
assert(Py_REFCNT(frame_frame_datastruct) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_datastruct$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_datastruct$__spec__(tstate);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_datastruct, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_datastruct->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_datastruct, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_datastruct);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_annotations_1;
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_ab4b8895c76990ee22ef1eb646200841);

tmp_assign_source_5 = MAKE_FUNCTION_datastruct$$$function__1_make_pair(tstate, tmp_annotations_1);

UPDATE_STRING_DICT1(moduledict_datastruct, (Nuitka_StringObject *)mod_consts.const_str_plain_make_pair, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
PyObject *tmp_annotations_2;
tmp_annotations_2 = DICT_COPY(tstate, mod_consts.const_dict_31e68efd53cbc16164a8ef71d623a7e3);

tmp_assign_source_6 = MAKE_FUNCTION_datastruct$$$function__2_make_dict(tstate, tmp_annotations_2);

UPDATE_STRING_DICT1(moduledict_datastruct, (Nuitka_StringObject *)mod_consts.const_str_plain_make_dict, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;
PyObject *tmp_annotations_3;
tmp_annotations_3 = DICT_COPY(tstate, mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6);

tmp_assign_source_7 = MAKE_FUNCTION_datastruct$$$function__3_first(tstate, tmp_annotations_3);

UPDATE_STRING_DICT1(moduledict_datastruct, (Nuitka_StringObject *)mod_consts.const_str_plain_first, tmp_assign_source_7);
}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_annotations_4;
tmp_annotations_4 = DICT_COPY(tstate, mod_consts.const_dict_931d4e41440e5948c9eaaba647e23bf6);

tmp_assign_source_8 = MAKE_FUNCTION_datastruct$$$function__4_pair_sum(tstate, tmp_annotations_4);

UPDATE_STRING_DICT1(moduledict_datastruct, (Nuitka_StringObject *)mod_consts.const_str_plain_pair_sum, tmp_assign_source_8);
}
{
PyObject *tmp_assign_source_9;
PyObject *tmp_annotations_5;
tmp_annotations_5 = DICT_COPY(tstate, mod_consts.const_dict_13b9992d5bea1b1702711b17dbcebe8e);

tmp_assign_source_9 = MAKE_FUNCTION_datastruct$$$function__5_boolop(tstate, tmp_annotations_5);

UPDATE_STRING_DICT1(moduledict_datastruct, (Nuitka_StringObject *)mod_consts.const_str_plain_boolop, tmp_assign_source_9);
}
{
PyObject *tmp_assign_source_10;
PyObject *tmp_annotations_6;
tmp_annotations_6 = DICT_COPY(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);

tmp_assign_source_10 = MAKE_FUNCTION_datastruct$$$function__6_ternary(tstate, tmp_annotations_6);

UPDATE_STRING_DICT1(moduledict_datastruct, (Nuitka_StringObject *)mod_consts.const_str_plain_ternary, tmp_assign_source_10);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("datastruct", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "datastruct" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_datastruct);
    return module_datastruct;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_datastruct, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("datastruct", false);

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
            moduledict_datastruct,
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
static struct PyModuleDef mdef_datastruct = {
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
            moduledict_datastruct,
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

static PyObject *PyInit_datastruct_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_datastruct(tstate, module, getLoaderEntry("datastruct"));

#if PYTHON_VERSION < 0x300
    // Our "__file__" value will not be respected by CPython and one
    // way we can avoid it, is by having a capsule type, that when
    // it gets released, we are called and repair the value.

    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_datastruct, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_datastruct,
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

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_datastruct, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_datastruct_slot(PyObject *module) {
    PyObject *result = PyInit_datastruct_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_datastruct)(void) {
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
    mdef_datastruct.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_datastruct);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_datastruct_slot},
        {0, NULL}
    };

    mdef_datastruct.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_datastruct);
#elif PYTHON_VERSION >= 0x300
    return PyInit_datastruct_phase2(module);
#else
    PyInit_datastruct_phase2(module);
#endif
}
