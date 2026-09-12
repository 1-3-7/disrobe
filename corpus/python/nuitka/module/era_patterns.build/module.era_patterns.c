/* Generated code for Python module 'era_patterns'
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



/* The "module_era_patterns" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_era_patterns;
PyDictObject *moduledict_era_patterns;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_int_pos_3;
PyObject *const_str_plain_n;
PyObject *const_str_plain_gen_squares;
PyObject *const_int_neg_2;
PyObject *const_int_pos_10;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_dict_9faf02f4082525ec9fbc5b8cd2fb2018;
PyObject *const_str_plain_set_comp;
PyObject *const_dict_870bcd6f248dd58b156871248cb8fd1e;
PyObject *const_dict_a651edb4508386ac796e5d15189d2d4b;
PyObject *const_str_plain_multi_except;
PyObject *const_dict_42672f778c35690e25f4da42ecec8345;
PyObject *const_str_plain_except_as;
PyObject *const_str_digest_fefae4cc51311ec2713aea2420882cb2;
PyObject *const_str_digest_5b03699683bcb9dac54fca007a0574a5;
PyObject *const_tuple_str_plain_a_str_plain_exc_tuple;
PyObject *const_tuple_str_plain_n_str_plain_i_tuple;
PyObject *const_tuple_str_plain_a_str_plain_b_tuple;
PyObject *const_tuple_str_plain_n_tuple;
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
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("era_patterns"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 20) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 20 values, got %d\n",
                    UN_TRANSLATE("era_patterns"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_3", mod_consts.const_int_pos_3);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_int_pos_3);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_n", mod_consts.const_str_plain_n);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_plain_n);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_gen_squares", mod_consts.const_str_plain_gen_squares);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_str_plain_gen_squares);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_neg_2", mod_consts.const_int_neg_2);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_int_neg_2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_10", mod_consts.const_int_pos_10);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_int_pos_10);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_9faf02f4082525ec9fbc5b8cd2fb2018", mod_consts.const_dict_9faf02f4082525ec9fbc5b8cd2fb2018);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_dict_9faf02f4082525ec9fbc5b8cd2fb2018);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_set_comp", mod_consts.const_str_plain_set_comp);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_str_plain_set_comp);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_870bcd6f248dd58b156871248cb8fd1e", mod_consts.const_dict_870bcd6f248dd58b156871248cb8fd1e);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_dict_870bcd6f248dd58b156871248cb8fd1e);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b", mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_multi_except", mod_consts.const_str_plain_multi_except);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_str_plain_multi_except);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_42672f778c35690e25f4da42ecec8345", mod_consts.const_dict_42672f778c35690e25f4da42ecec8345);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_dict_42672f778c35690e25f4da42ecec8345);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_except_as", mod_consts.const_str_plain_except_as);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_str_plain_except_as);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_fefae4cc51311ec2713aea2420882cb2", mod_consts.const_str_digest_fefae4cc51311ec2713aea2420882cb2);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_str_digest_fefae4cc51311ec2713aea2420882cb2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5", mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_exc_tuple", mod_consts.const_tuple_str_plain_a_str_plain_exc_tuple);
mod_consts_hash[16] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_exc_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_i_tuple", mod_consts.const_tuple_str_plain_n_str_plain_i_tuple);
mod_consts_hash[17] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_i_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
mod_consts_hash[18] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
mod_consts_hash[19] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple);
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
void checkModuleConstants_era_patterns(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_3", mod_consts.const_int_pos_3);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_int_pos_3) && "mod_consts.const_int_pos_3");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_n", mod_consts.const_str_plain_n);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_plain_n) && "mod_consts.const_str_plain_n");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_gen_squares", mod_consts.const_str_plain_gen_squares);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_str_plain_gen_squares) && "mod_consts.const_str_plain_gen_squares");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_neg_2", mod_consts.const_int_neg_2);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_int_neg_2) && "mod_consts.const_int_neg_2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_10", mod_consts.const_int_pos_10);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_int_pos_10) && "mod_consts.const_int_pos_10");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_9faf02f4082525ec9fbc5b8cd2fb2018", mod_consts.const_dict_9faf02f4082525ec9fbc5b8cd2fb2018);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_dict_9faf02f4082525ec9fbc5b8cd2fb2018) && "mod_consts.const_dict_9faf02f4082525ec9fbc5b8cd2fb2018");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_set_comp", mod_consts.const_str_plain_set_comp);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_str_plain_set_comp) && "mod_consts.const_str_plain_set_comp");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_870bcd6f248dd58b156871248cb8fd1e", mod_consts.const_dict_870bcd6f248dd58b156871248cb8fd1e);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_dict_870bcd6f248dd58b156871248cb8fd1e) && "mod_consts.const_dict_870bcd6f248dd58b156871248cb8fd1e");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b", mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b) && "mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_multi_except", mod_consts.const_str_plain_multi_except);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_str_plain_multi_except) && "mod_consts.const_str_plain_multi_except");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_42672f778c35690e25f4da42ecec8345", mod_consts.const_dict_42672f778c35690e25f4da42ecec8345);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_dict_42672f778c35690e25f4da42ecec8345) && "mod_consts.const_dict_42672f778c35690e25f4da42ecec8345");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_except_as", mod_consts.const_str_plain_except_as);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_str_plain_except_as) && "mod_consts.const_str_plain_except_as");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_fefae4cc51311ec2713aea2420882cb2", mod_consts.const_str_digest_fefae4cc51311ec2713aea2420882cb2);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_str_digest_fefae4cc51311ec2713aea2420882cb2) && "mod_consts.const_str_digest_fefae4cc51311ec2713aea2420882cb2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5", mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5) && "mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_exc_tuple", mod_consts.const_tuple_str_plain_a_str_plain_exc_tuple);
assert(mod_consts_hash[16] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_exc_tuple) && "mod_consts.const_tuple_str_plain_a_str_plain_exc_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_i_tuple", mod_consts.const_tuple_str_plain_n_str_plain_i_tuple);
assert(mod_consts_hash[17] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_i_tuple) && "mod_consts.const_tuple_str_plain_n_str_plain_i_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
assert(mod_consts_hash[18] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple) && "mod_consts.const_tuple_str_plain_a_str_plain_b_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_tuple", mod_consts.const_tuple_str_plain_n_tuple);
assert(mod_consts_hash[19] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_tuple) && "mod_consts.const_tuple_str_plain_n_tuple");
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
static PyObject *module_var_accessor_era_patterns$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_era_patterns->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_era_patterns->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_era_patterns->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_b096599226defd422cb56b08b4d9939a;
static PyCodeObject *code_objects_bdbe54201145f86ac389ba631f430f4d;
static PyCodeObject *code_objects_8e2bb4d3f8ffb620f2e32552a869f326;
static PyCodeObject *code_objects_514423927967e52152d01f1f4ba79f94;
static PyCodeObject *code_objects_a9a687dd03c6e7e082a2e4bd55f24f29;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_fefae4cc51311ec2713aea2420882cb2); CHECK_OBJECT(module_filename_obj);
code_objects_b096599226defd422cb56b08b4d9939a = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5, mod_consts.const_str_digest_5b03699683bcb9dac54fca007a0574a5, NULL, NULL, 0, 0, 0);
code_objects_bdbe54201145f86ac389ba631f430f4d = MAKE_CODE_OBJECT(module_filename_obj, 19, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_except_as, mod_consts.const_str_plain_except_as, mod_consts.const_tuple_str_plain_a_str_plain_exc_tuple, NULL, 1, 0, 0);
code_objects_8e2bb4d3f8ffb620f2e32552a869f326 = MAKE_CODE_OBJECT(module_filename_obj, 5, CO_GENERATOR | CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_gen_squares, mod_consts.const_str_plain_gen_squares, mod_consts.const_tuple_str_plain_n_str_plain_i_tuple, NULL, 1, 0, 0);
code_objects_514423927967e52152d01f1f4ba79f94 = MAKE_CODE_OBJECT(module_filename_obj, 10, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_multi_except, mod_consts.const_str_plain_multi_except, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple, NULL, 2, 0, 0);
code_objects_a9a687dd03c6e7e082a2e4bd55f24f29 = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_set_comp, mod_consts.const_str_plain_set_comp, mod_consts.const_tuple_str_plain_n_tuple, NULL, 1, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_GENERATOR_era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares(PyThreadState *tstate, struct Nuitka_CellObject **closure);


static PyObject *MAKE_FUNCTION_era_patterns$$$function__1_set_comp(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_era_patterns$$$function__2_gen_squares(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_era_patterns$$$function__3_multi_except(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_era_patterns$$$function__4_except_as(PyThreadState *tstate, PyObject *annotations);


// The module function definitions.
static PyObject *impl_era_patterns$$$function__1_set_comp(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_n = python_pars[0];
PyObject *outline_0_var_i = NULL;
PyObject *tmp_setcontraction_1__$0 = NULL;
PyObject *tmp_setcontraction_1__contraction = NULL;
PyObject *tmp_setcontraction_1__iter_value_0 = NULL;
struct Nuitka_FrameObject *frame_frame_era_patterns$$$function__1_set_comp;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
int tmp_res;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
static struct Nuitka_FrameObject *cache_frame_frame_era_patterns$$$function__1_set_comp = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_era_patterns$$$function__1_set_comp)) {
    Py_XDECREF(cache_frame_frame_era_patterns$$$function__1_set_comp);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_era_patterns$$$function__1_set_comp == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_era_patterns$$$function__1_set_comp = MAKE_FUNCTION_FRAME(tstate, code_objects_a9a687dd03c6e7e082a2e4bd55f24f29, module_era_patterns, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_era_patterns$$$function__1_set_comp->m_type_description == NULL);
frame_frame_era_patterns$$$function__1_set_comp = cache_frame_frame_era_patterns$$$function__1_set_comp;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_era_patterns$$$function__1_set_comp);
assert(Py_REFCNT(frame_frame_era_patterns$$$function__1_set_comp) == 2);

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
    PyObject *old = tmp_setcontraction_1__$0;
    tmp_setcontraction_1__$0 = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = PySet_New(NULL);
{
    PyObject *old = tmp_setcontraction_1__contraction;
    tmp_setcontraction_1__contraction = tmp_assign_source_2;
    Py_XDECREF(old);
}

}
// Tried code:
loop_start_1:;
{
PyObject *tmp_next_source_1;
PyObject *tmp_assign_source_3;
CHECK_OBJECT(tmp_setcontraction_1__$0);
tmp_next_source_1 = tmp_setcontraction_1__$0;
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
    PyObject *old = tmp_setcontraction_1__iter_value_0;
    tmp_setcontraction_1__iter_value_0 = tmp_assign_source_3;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_4;
CHECK_OBJECT(tmp_setcontraction_1__iter_value_0);
tmp_assign_source_4 = tmp_setcontraction_1__iter_value_0;
{
    PyObject *old = outline_0_var_i;
    outline_0_var_i = tmp_assign_source_4;
    Py_INCREF(outline_0_var_i);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_add_set_1;
PyObject *tmp_add_value_1;
PyObject *tmp_mod_expr_left_1;
PyObject *tmp_mod_expr_right_1;
CHECK_OBJECT(tmp_setcontraction_1__contraction);
tmp_add_set_1 = tmp_setcontraction_1__contraction;
CHECK_OBJECT(outline_0_var_i);
tmp_mod_expr_left_1 = outline_0_var_i;
tmp_mod_expr_right_1 = mod_consts.const_int_pos_3;
tmp_add_value_1 = BINARY_OPERATION_MOD_OBJECT_OBJECT_LONG(tmp_mod_expr_left_1, tmp_mod_expr_right_1);
if (tmp_add_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "o";
    goto try_except_handler_2;
}
assert(PySet_Check(tmp_add_set_1));
tmp_res = PySet_Add(tmp_add_set_1, tmp_add_value_1);
CHECK_OBJECT(tmp_add_value_1);
Py_DECREF(tmp_add_value_1);
if (tmp_res == -1) {
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
CHECK_OBJECT(tmp_setcontraction_1__contraction);
tmp_return_value = tmp_setcontraction_1__contraction;
Py_INCREF(tmp_return_value);
goto try_return_handler_2;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_2:;
CHECK_OBJECT(tmp_setcontraction_1__$0);
CHECK_OBJECT(tmp_setcontraction_1__$0);
Py_DECREF(tmp_setcontraction_1__$0);
tmp_setcontraction_1__$0 = NULL;
CHECK_OBJECT(tmp_setcontraction_1__contraction);
CHECK_OBJECT(tmp_setcontraction_1__contraction);
Py_DECREF(tmp_setcontraction_1__contraction);
tmp_setcontraction_1__contraction = NULL;
Py_XDECREF(tmp_setcontraction_1__iter_value_0);
tmp_setcontraction_1__iter_value_0 = NULL;
goto try_return_handler_1;
// Exception handler code:
try_except_handler_2:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(tmp_setcontraction_1__$0);
CHECK_OBJECT(tmp_setcontraction_1__$0);
Py_DECREF(tmp_setcontraction_1__$0);
tmp_setcontraction_1__$0 = NULL;
CHECK_OBJECT(tmp_setcontraction_1__contraction);
CHECK_OBJECT(tmp_setcontraction_1__contraction);
Py_DECREF(tmp_setcontraction_1__contraction);
tmp_setcontraction_1__contraction = NULL;
Py_XDECREF(tmp_setcontraction_1__iter_value_0);
tmp_setcontraction_1__iter_value_0 = NULL;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_era_patterns$$$function__1_set_comp, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_era_patterns$$$function__1_set_comp->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_era_patterns$$$function__1_set_comp, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_era_patterns$$$function__1_set_comp,
    type_description_1,
    par_n
);


// Release cached frame if used for exception.
if (frame_frame_era_patterns$$$function__1_set_comp == cache_frame_frame_era_patterns$$$function__1_set_comp) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_era_patterns$$$function__1_set_comp);
    cache_frame_frame_era_patterns$$$function__1_set_comp = NULL;
}

assertFrameObject(frame_frame_era_patterns$$$function__1_set_comp);

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


static PyObject *impl_era_patterns$$$function__2_gen_squares(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
struct Nuitka_CellObject *par_n = Nuitka_Cell_New1(python_pars[0]);
PyObject *tmp_return_value = NULL;

    // Actual function body.
// Tried code:
{
struct Nuitka_CellObject *tmp_closure_1[1];
tmp_closure_1[0] = par_n;
Py_INCREF(tmp_closure_1[0]);
tmp_return_value = MAKE_GENERATOR_era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares(tstate, tmp_closure_1);

goto try_return_handler_1;
}
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
CHECK_OBJECT(par_n);
CHECK_OBJECT(par_n);
Py_DECREF(par_n);
par_n = NULL;
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



#if 1
struct era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares_locals {
PyObject *var_i;
PyObject *tmp_for_loop_1__for_iterator;
PyObject *tmp_for_loop_1__iter_value;
char const *type_description_1;
struct Nuitka_ExceptionPreservationItem exception_state;
int exception_lineno;
char yield_tmps[1024];
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
int exception_keeper_lineno_2;
};
#endif

static PyObject *era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares_context(PyThreadState *tstate, struct Nuitka_GeneratorObject *generator, PyObject *yield_return_value) {
    CHECK_OBJECT(generator);
    assert(Nuitka_Generator_Check((PyObject *)generator));
    CHECK_OBJECT_X(yield_return_value);

#if 1
    // Heap access.
struct era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares_locals *generator_heap = (struct era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares_locals *)generator->m_heap_storage;
#endif

    // Dispatch to yield based on return label index:
switch(generator->m_yield_return_index) {
case 1: goto yield_return_1;
}

    // Local variable initialization
NUITKA_MAY_BE_UNUSED nuitka_void tmp_unused;
static struct Nuitka_FrameObject *cache_m_frame = NULL;
generator_heap->var_i = NULL;
generator_heap->tmp_for_loop_1__for_iterator = NULL;
generator_heap->tmp_for_loop_1__iter_value = NULL;
generator_heap->type_description_1 = NULL;
generator_heap->exception_state = Empty_Nuitka_ExceptionPreservationItem;
generator_heap->exception_lineno = 0;

    // Actual generator function body.
// Tried code:
if (isFrameUnusable(cache_m_frame)) {
    Py_XDECREF(cache_m_frame);

#if _DEBUG_REFCOUNTS
    if (cache_m_frame == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_m_frame = MAKE_FUNCTION_FRAME(tstate, code_objects_8e2bb4d3f8ffb620f2e32552a869f326, module_era_patterns, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_m_frame->m_type_description == NULL);
generator->m_frame = cache_m_frame;
// Mark the frame object as in use, ref count 1 will be up for reuse.
Py_INCREF(generator->m_frame);
assert(Py_REFCNT(generator->m_frame) == 2); // Frame stack

Nuitka_SetFrameGenerator(generator->m_frame, (PyObject *)generator);

assert(generator->m_frame->m_frame.f_back == NULL);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackGeneratorCompiledFrame(tstate, generator->m_frame);
assert(Py_REFCNT(generator->m_frame) == 2);

// Store currently existing exception as the one to publish again when we
// yield or yield from.
STORE_GENERATOR_EXCEPTION(tstate, generator);

// Framed code:
{
PyObject *tmp_assign_source_1;
PyObject *tmp_iter_arg_1;
PyObject *tmp_xrange_low_1;
if (Nuitka_Cell_GET(generator->m_closure[0]) == NULL) {

FORMAT_UNBOUND_CLOSURE_ERROR(tstate, &generator_heap->exception_state, mod_consts.const_str_plain_n);
CHAIN_EXCEPTION(tstate, generator_heap->exception_state.exception_value);

generator_heap->exception_lineno = 6;
generator_heap->type_description_1 = "co";
    goto frame_exception_exit_1;
}

tmp_xrange_low_1 = Nuitka_Cell_GET(generator->m_closure[0]);
tmp_iter_arg_1 = BUILTIN_XRANGE1(tstate, tmp_xrange_low_1);
if (tmp_iter_arg_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &generator_heap->exception_state);


generator_heap->exception_lineno = 6;
generator_heap->type_description_1 = "co";
    goto frame_exception_exit_1;
}
tmp_assign_source_1 = MAKE_ITERATOR(tstate, tmp_iter_arg_1);
CHECK_OBJECT(tmp_iter_arg_1);
Py_DECREF(tmp_iter_arg_1);
if (tmp_assign_source_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &generator_heap->exception_state);


generator_heap->exception_lineno = 6;
generator_heap->type_description_1 = "co";
    goto frame_exception_exit_1;
}
{
    PyObject *old = generator_heap->tmp_for_loop_1__for_iterator;
    generator_heap->tmp_for_loop_1__for_iterator = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
// Tried code:
loop_start_1:;
{
PyObject *tmp_next_source_1;
PyObject *tmp_assign_source_2;
CHECK_OBJECT(generator_heap->tmp_for_loop_1__for_iterator);
tmp_next_source_1 = generator_heap->tmp_for_loop_1__for_iterator;
tmp_assign_source_2 = ITERATOR_NEXT_ITERATOR(tmp_next_source_1);
if (tmp_assign_source_2 == NULL) {
    if (CHECK_AND_CLEAR_STOP_ITERATION_OCCURRED(tstate)) {

        goto loop_end_1;
    } else {

        FETCH_ERROR_OCCURRED_STATE(tstate, &generator_heap->exception_state);
generator_heap->type_description_1 = "co";
generator_heap->exception_lineno = 6;
        goto try_except_handler_2;
    }
}

{
    PyObject *old = generator_heap->tmp_for_loop_1__iter_value;
    generator_heap->tmp_for_loop_1__iter_value = tmp_assign_source_2;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_3;
CHECK_OBJECT(generator_heap->tmp_for_loop_1__iter_value);
tmp_assign_source_3 = generator_heap->tmp_for_loop_1__iter_value;
{
    PyObject *old = generator_heap->var_i;
    generator_heap->var_i = tmp_assign_source_3;
    Py_INCREF(generator_heap->var_i);
    Py_XDECREF(old);
}

}
{
PyObject *tmp_expression_value_1;
PyObject *tmp_mult_expr_left_1;
PyObject *tmp_mult_expr_right_1;
NUITKA_MAY_BE_UNUSED PyObject *tmp_yield_result_1;
CHECK_OBJECT(generator_heap->var_i);
tmp_mult_expr_left_1 = generator_heap->var_i;
CHECK_OBJECT(generator_heap->var_i);
tmp_mult_expr_right_1 = generator_heap->var_i;
tmp_expression_value_1 = BINARY_OPERATION_MULT_OBJECT_OBJECT_OBJECT(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
if (tmp_expression_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &generator_heap->exception_state);


generator_heap->exception_lineno = 7;
generator_heap->type_description_1 = "co";
    goto try_except_handler_2;
}
Nuitka_PreserveHeap(generator_heap->yield_tmps, &tmp_mult_expr_left_1, sizeof(PyObject *), &tmp_mult_expr_right_1, sizeof(PyObject *), NULL);
generator->m_yield_return_index = 1;
return tmp_expression_value_1;
yield_return_1:
Nuitka_RestoreHeap(generator_heap->yield_tmps, &tmp_mult_expr_left_1, sizeof(PyObject *), &tmp_mult_expr_right_1, sizeof(PyObject *), NULL);
if (yield_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &generator_heap->exception_state);


generator_heap->exception_lineno = 7;
generator_heap->type_description_1 = "co";
    goto try_except_handler_2;
}
tmp_yield_result_1 = yield_return_value;
CHECK_OBJECT(tmp_yield_result_1);
Py_DECREF(tmp_yield_result_1);
}
if (CONSIDER_THREADING(tstate) == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &generator_heap->exception_state);


generator_heap->exception_lineno = 6;
generator_heap->type_description_1 = "co";
    goto try_except_handler_2;
}
goto loop_start_1;
loop_end_1:;
goto try_end_1;
// Exception handler code:
try_except_handler_2:;
generator_heap->exception_keeper_lineno_1 = generator_heap->exception_lineno;
generator_heap->exception_lineno = 0;
generator_heap->exception_keeper_name_1 = generator_heap->exception_state;
INIT_ERROR_OCCURRED_STATE(&generator_heap->exception_state);

Py_XDECREF(generator_heap->tmp_for_loop_1__iter_value);
generator_heap->tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(generator_heap->tmp_for_loop_1__for_iterator);
CHECK_OBJECT(generator_heap->tmp_for_loop_1__for_iterator);
Py_DECREF(generator_heap->tmp_for_loop_1__for_iterator);
generator_heap->tmp_for_loop_1__for_iterator = NULL;
// Re-raise.
generator_heap->exception_state = generator_heap->exception_keeper_name_1;
generator_heap->exception_lineno = generator_heap->exception_keeper_lineno_1;

goto frame_exception_exit_1;
// End of try:
try_end_1:;

// Release exception attached to the frame
DROP_GENERATOR_EXCEPTION(generator);



goto frame_no_exception_1;
frame_exception_exit_1:;

// If it's not an exit exception, consider and create a traceback for it.
if (!EXCEPTION_STATE_MATCH_GENERATOR(tstate, &generator_heap->exception_state)) {
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&generator_heap->exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(generator->m_frame, generator_heap->exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&generator_heap->exception_state, exception_tb);
    } else if ((generator_heap->exception_lineno != 0) && (exception_tb->tb_frame != &generator->m_frame->m_frame)) {
        exception_tb = ADD_TRACEBACK(exception_tb, generator->m_frame, generator_heap->exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&generator_heap->exception_state, exception_tb);
    }

Nuitka_Frame_AttachLocals(
    generator->m_frame,
    generator_heap->type_description_1,
    generator->m_closure[0],
    generator_heap->var_i
);


    // Release cached frame if used for exception.
    if (generator->m_frame == cache_m_frame) {
#if _DEBUG_REFCOUNTS
        count_active_frame_cache_instances -= 1;
        count_released_frame_cache_instances += 1;
#endif

        Py_DECREF(cache_m_frame);
        cache_m_frame = NULL;
    }

    assertFrameObject(generator->m_frame);
}

// Release exception attached to the frame
DROP_GENERATOR_EXCEPTION(generator);


// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
goto try_end_2;
// Exception handler code:
try_except_handler_1:;
generator_heap->exception_keeper_lineno_2 = generator_heap->exception_lineno;
generator_heap->exception_lineno = 0;
generator_heap->exception_keeper_name_2 = generator_heap->exception_state;
INIT_ERROR_OCCURRED_STATE(&generator_heap->exception_state);

Py_XDECREF(generator_heap->var_i);
generator_heap->var_i = NULL;
// Re-raise.
generator_heap->exception_state = generator_heap->exception_keeper_name_2;
generator_heap->exception_lineno = generator_heap->exception_keeper_lineno_2;

goto function_exception_exit;
// End of try:
try_end_2:;
Py_XDECREF(generator_heap->tmp_for_loop_1__iter_value);
generator_heap->tmp_for_loop_1__iter_value = NULL;
CHECK_OBJECT(generator_heap->tmp_for_loop_1__for_iterator);
CHECK_OBJECT(generator_heap->tmp_for_loop_1__for_iterator);
Py_DECREF(generator_heap->tmp_for_loop_1__for_iterator);
generator_heap->tmp_for_loop_1__for_iterator = NULL;
Py_XDECREF(generator_heap->var_i);
generator_heap->var_i = NULL;


    return NULL;

    function_exception_exit:

    CHECK_EXCEPTION_STATE(&generator_heap->exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &generator_heap->exception_state);

    return NULL;

}

static PyObject *MAKE_GENERATOR_era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares(PyThreadState *tstate, struct Nuitka_CellObject **closure) {
    return Nuitka_Generator_New(
        era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares_context,
        module_era_patterns,
        mod_consts.const_str_plain_gen_squares,
#if PYTHON_VERSION >= 0x350
        NULL,
#endif
        code_objects_8e2bb4d3f8ffb620f2e32552a869f326,
        closure,
        1,
#if 1
        sizeof(struct era_patterns$$$function__2_gen_squares$$$genobj__1_gen_squares_locals)
#else
        0
#endif
    );
}


static PyObject *impl_era_patterns$$$function__3_multi_except(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
struct Nuitka_FrameObject *frame_frame_era_patterns$$$function__3_multi_except;
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
static struct Nuitka_FrameObject *cache_frame_frame_era_patterns$$$function__3_multi_except = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_era_patterns$$$function__3_multi_except)) {
    Py_XDECREF(cache_frame_frame_era_patterns$$$function__3_multi_except);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_era_patterns$$$function__3_multi_except == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_era_patterns$$$function__3_multi_except = MAKE_FUNCTION_FRAME(tstate, code_objects_514423927967e52152d01f1f4ba79f94, module_era_patterns, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_era_patterns$$$function__3_multi_except->m_type_description == NULL);
frame_frame_era_patterns$$$function__3_multi_except = cache_frame_frame_era_patterns$$$function__3_multi_except;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_era_patterns$$$function__3_multi_except);
assert(Py_REFCNT(frame_frame_era_patterns$$$function__3_multi_except) == 2);

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


exception_lineno = 12;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_era_patterns$$$function__3_multi_except, exception_keeper_lineno_1);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_keeper_name_1, exception_tb);
    } else if (exception_keeper_lineno_1 != 0) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_era_patterns$$$function__3_multi_except, exception_keeper_lineno_1);
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
tmp_return_value = const_int_neg_1;
Py_INCREF(tmp_return_value);
goto try_return_handler_2;
goto branch_end_1;
branch_no_1:;
{
bool tmp_condition_result_2;
PyObject *tmp_cmp_expr_left_2;
PyObject *tmp_cmp_expr_right_2;
tmp_cmp_expr_left_2 = EXC_TYPE(tstate);
tmp_cmp_expr_right_2 = PyExc_TypeError;
tmp_res = EXCEPTION_MATCH_BOOL(tstate, tmp_cmp_expr_left_2, tmp_cmp_expr_right_2);
assert(!(tmp_res == -1));
tmp_condition_result_2 = (tmp_res != 0) ? true : false;
if (tmp_condition_result_2 != false) {
    goto branch_yes_2;
} else {
    goto branch_no_2;
}
}
branch_yes_2:;
tmp_return_value = mod_consts.const_int_neg_2;
Py_INCREF(tmp_return_value);
goto try_return_handler_2;
goto branch_end_2;
branch_no_2:;
tmp_result = RERAISE_EXCEPTION(tstate, &exception_state);
if (unlikely(tmp_result == false)) {
    exception_lineno = 11;
}

{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);

    if ((exception_tb != NULL) && (exception_tb->tb_frame == &frame_frame_era_patterns$$$function__3_multi_except->m_frame)) {
        frame_frame_era_patterns$$$function__3_multi_except->m_frame.f_lineno = exception_tb->tb_lineno;
    }
}
type_description_1 = "oo";
goto try_except_handler_2;
branch_end_2:;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_era_patterns$$$function__3_multi_except, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_era_patterns$$$function__3_multi_except->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_era_patterns$$$function__3_multi_except, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_era_patterns$$$function__3_multi_except,
    type_description_1,
    par_a,
    par_b
);


// Release cached frame if used for exception.
if (frame_frame_era_patterns$$$function__3_multi_except == cache_frame_frame_era_patterns$$$function__3_multi_except) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_era_patterns$$$function__3_multi_except);
    cache_frame_frame_era_patterns$$$function__3_multi_except = NULL;
}

assertFrameObject(frame_frame_era_patterns$$$function__3_multi_except);

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


static PyObject *impl_era_patterns$$$function__4_except_as(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *var_exc = NULL;
struct Nuitka_FrameObject *frame_frame_era_patterns$$$function__4_except_as;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionStackItem exception_preserved_1;
int tmp_res;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_3;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_3;
static struct Nuitka_FrameObject *cache_frame_frame_era_patterns$$$function__4_except_as = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_era_patterns$$$function__4_except_as)) {
    Py_XDECREF(cache_frame_frame_era_patterns$$$function__4_except_as);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_era_patterns$$$function__4_except_as == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_era_patterns$$$function__4_except_as = MAKE_FUNCTION_FRAME(tstate, code_objects_bdbe54201145f86ac389ba631f430f4d, module_era_patterns, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_era_patterns$$$function__4_except_as->m_type_description == NULL);
frame_frame_era_patterns$$$function__4_except_as = cache_frame_frame_era_patterns$$$function__4_except_as;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_era_patterns$$$function__4_except_as);
assert(Py_REFCNT(frame_frame_era_patterns$$$function__4_except_as) == 2);

// Framed code:
// Tried code:
{
PyObject *tmp_unicode_arg_1;
PyObject *tmp_floordiv_expr_left_1;
PyObject *tmp_floordiv_expr_right_1;
tmp_floordiv_expr_left_1 = mod_consts.const_int_pos_10;
CHECK_OBJECT(par_a);
tmp_floordiv_expr_right_1 = par_a;
tmp_unicode_arg_1 = BINARY_OPERATION_FLOORDIV_OBJECT_LONG_OBJECT(tmp_floordiv_expr_left_1, tmp_floordiv_expr_right_1);
if (tmp_unicode_arg_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 21;
type_description_1 = "oo";
    goto try_except_handler_1;
}
tmp_return_value = BUILTIN_UNICODE1(tmp_unicode_arg_1);
CHECK_OBJECT(tmp_unicode_arg_1);
Py_DECREF(tmp_unicode_arg_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 21;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_era_patterns$$$function__4_except_as, exception_keeper_lineno_1);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_keeper_name_1, exception_tb);
    } else if (exception_keeper_lineno_1 != 0) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_era_patterns$$$function__4_except_as, exception_keeper_lineno_1);
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
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = EXC_VALUE(tstate);
CHECK_OBJECT(tmp_assign_source_1); 
{
    PyObject *old = var_exc;
    var_exc = tmp_assign_source_1;
    Py_INCREF(var_exc);
    Py_XDECREF(old);
}

}
// Tried code:
{
PyObject *tmp_expression_value_1;
PyObject *tmp_type_arg_1;
CHECK_OBJECT(var_exc);
tmp_type_arg_1 = var_exc;
tmp_expression_value_1 = BUILTIN_TYPE1(tmp_type_arg_1);
assert(!(tmp_expression_value_1 == NULL));
tmp_return_value = LOOKUP_ATTRIBUTE(tstate, tmp_expression_value_1, const_str_plain___name__);
CHECK_OBJECT(tmp_expression_value_1);
Py_DECREF(tmp_expression_value_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 23;
type_description_1 = "oo";
    goto try_except_handler_3;
}
goto try_return_handler_3;
}
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_3:;
Py_XDECREF(var_exc);
var_exc = NULL;

goto try_return_handler_2;
// Exception handler code:
try_except_handler_3:;
exception_keeper_lineno_2 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_2 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_exc);
var_exc = NULL;

// Re-raise.
exception_state = exception_keeper_name_2;
exception_lineno = exception_keeper_lineno_2;

goto try_except_handler_2;
// End of try:
goto branch_end_1;
branch_no_1:;
tmp_result = RERAISE_EXCEPTION(tstate, &exception_state);
if (unlikely(tmp_result == false)) {
    exception_lineno = 20;
}

{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);

    if ((exception_tb != NULL) && (exception_tb->tb_frame == &frame_frame_era_patterns$$$function__4_except_as->m_frame)) {
        frame_frame_era_patterns$$$function__4_except_as->m_frame.f_lineno = exception_tb->tb_lineno;
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
exception_keeper_lineno_3 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_3 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

// Restore previous exception id 1.
SET_CURRENT_EXCEPTION(tstate, &exception_preserved_1);

// Re-raise.
exception_state = exception_keeper_name_3;
exception_lineno = exception_keeper_lineno_3;

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
        exception_tb = MAKE_TRACEBACK(frame_frame_era_patterns$$$function__4_except_as, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_era_patterns$$$function__4_except_as->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_era_patterns$$$function__4_except_as, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_era_patterns$$$function__4_except_as,
    type_description_1,
    par_a,
    var_exc
);


// Release cached frame if used for exception.
if (frame_frame_era_patterns$$$function__4_except_as == cache_frame_frame_era_patterns$$$function__4_except_as) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_era_patterns$$$function__4_except_as);
    cache_frame_frame_era_patterns$$$function__4_except_as = NULL;
}

assertFrameObject(frame_frame_era_patterns$$$function__4_except_as);

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
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_a);
Py_DECREF(par_a);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}



static PyObject *MAKE_FUNCTION_era_patterns$$$function__1_set_comp(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_era_patterns$$$function__1_set_comp,
        mod_consts.const_str_plain_set_comp,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_a9a687dd03c6e7e082a2e4bd55f24f29,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_era_patterns,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_era_patterns$$$function__2_gen_squares(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_era_patterns$$$function__2_gen_squares,
        mod_consts.const_str_plain_gen_squares,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_8e2bb4d3f8ffb620f2e32552a869f326,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_era_patterns,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_era_patterns$$$function__3_multi_except(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_era_patterns$$$function__3_multi_except,
        mod_consts.const_str_plain_multi_except,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_514423927967e52152d01f1f4ba79f94,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_era_patterns,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_era_patterns$$$function__4_except_as(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_era_patterns$$$function__4_except_as,
        mod_consts.const_str_plain_except_as,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_bdbe54201145f86ac389ba631f430f4d,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_era_patterns,
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

static function_impl_code const function_table_era_patterns[] = {
impl_era_patterns$$$function__1_set_comp,
impl_era_patterns$$$function__2_gen_squares,
impl_era_patterns$$$function__3_multi_except,
impl_era_patterns$$$function__4_except_as,
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

    return Nuitka_Function_GetFunctionState(function, function_table_era_patterns);
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
        module_era_patterns,
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
        function_table_era_patterns,
        sizeof(function_table_era_patterns) / sizeof(function_impl_code)
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
static char const *module_full_name = "era_patterns";
#endif

// Internal entry point for module code.
PyObject *module_code_era_patterns(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("era_patterns");

    // Store the module for future use.
    module_era_patterns = module;

    moduledict_era_patterns = MODULE_DICT(module_era_patterns);

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
        PRINT_STRING("era_patterns: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("era_patterns: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("era_patterns: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "era_patterns" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initera_patterns\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict_era_patterns,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_era_patterns,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_era_patterns,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_era_patterns,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_era_patterns,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_era_patterns);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_era_patterns);
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

        UPDATE_STRING_DICT1(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_era_patterns;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_era_patterns = MAKE_MODULE_FRAME(code_objects_b096599226defd422cb56b08b4d9939a, module_era_patterns);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_era_patterns);
assert(Py_REFCNT(frame_frame_era_patterns) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_era_patterns$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_era_patterns$__spec__(tstate);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_era_patterns, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_era_patterns->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_era_patterns, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_era_patterns);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_annotations_1;
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_9faf02f4082525ec9fbc5b8cd2fb2018);

tmp_assign_source_5 = MAKE_FUNCTION_era_patterns$$$function__1_set_comp(tstate, tmp_annotations_1);

UPDATE_STRING_DICT1(moduledict_era_patterns, (Nuitka_StringObject *)mod_consts.const_str_plain_set_comp, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
PyObject *tmp_annotations_2;
tmp_annotations_2 = DICT_COPY(tstate, mod_consts.const_dict_870bcd6f248dd58b156871248cb8fd1e);

tmp_assign_source_6 = MAKE_FUNCTION_era_patterns$$$function__2_gen_squares(tstate, tmp_annotations_2);

UPDATE_STRING_DICT1(moduledict_era_patterns, (Nuitka_StringObject *)mod_consts.const_str_plain_gen_squares, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;
PyObject *tmp_annotations_3;
tmp_annotations_3 = DICT_COPY(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);

tmp_assign_source_7 = MAKE_FUNCTION_era_patterns$$$function__3_multi_except(tstate, tmp_annotations_3);

UPDATE_STRING_DICT1(moduledict_era_patterns, (Nuitka_StringObject *)mod_consts.const_str_plain_multi_except, tmp_assign_source_7);
}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_annotations_4;
tmp_annotations_4 = DICT_COPY(tstate, mod_consts.const_dict_42672f778c35690e25f4da42ecec8345);

tmp_assign_source_8 = MAKE_FUNCTION_era_patterns$$$function__4_except_as(tstate, tmp_annotations_4);

UPDATE_STRING_DICT1(moduledict_era_patterns, (Nuitka_StringObject *)mod_consts.const_str_plain_except_as, tmp_assign_source_8);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("era_patterns", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "era_patterns" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_era_patterns);
    return module_era_patterns;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_era_patterns, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("era_patterns", false);

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
            moduledict_era_patterns,
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
static struct PyModuleDef mdef_era_patterns = {
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
            moduledict_era_patterns,
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

static PyObject *PyInit_era_patterns_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_era_patterns(tstate, module, getLoaderEntry("era_patterns"));

#if PYTHON_VERSION < 0x300
    // Our "__file__" value will not be respected by CPython and one
    // way we can avoid it, is by having a capsule type, that when
    // it gets released, we are called and repair the value.

    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_era_patterns, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_era_patterns,
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

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_era_patterns, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_era_patterns_slot(PyObject *module) {
    PyObject *result = PyInit_era_patterns_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_era_patterns)(void) {
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
    mdef_era_patterns.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_era_patterns);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_era_patterns_slot},
        {0, NULL}
    };

    mdef_era_patterns.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_era_patterns);
#elif PYTHON_VERSION >= 0x300
    return PyInit_era_patterns_phase2(module);
#else
    PyInit_era_patterns_phase2(module);
#endif
}
