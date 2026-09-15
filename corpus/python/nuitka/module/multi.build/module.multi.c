/* Generated code for Python module 'multi'
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



/* The "module_multi" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_multi;
PyDictObject *moduledict_multi;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_int_pos_2;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_dict_a651edb4508386ac796e5d15189d2d4b;
PyObject *const_str_plain_stats;
PyObject *const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12;
PyObject *const_str_plain_scale;
PyObject *const_str_plain_swap_sum;
PyObject *const_dict_ac2d17ccf098d71f8de0232b23b5a904;
PyObject *const_str_plain_absval;
PyObject *const_str_digest_2a2068285e6d366f221865fe9ac1f835;
PyObject *const_str_digest_74782ef1bf586a005b6e6892d14fdc52;
PyObject *const_tuple_str_plain_n_str_plain_r_tuple;
PyObject *const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple;
PyObject *const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple;
PyObject *const_tuple_str_plain_a_str_plain_b_tuple;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[16];
#endif

static PyObject *module_filename_obj = NULL;

/* Indicator if this modules private constants were created yet. */
static bool constants_created = false;

/* Function to create module private constants. */
static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("multi"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 16) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 16 values, got %d\n",
                    UN_TRANSLATE("multi"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_2", mod_consts.const_int_pos_2);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_int_pos_2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b", mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_stats", mod_consts.const_str_plain_stats);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_str_plain_stats);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12", mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_scale", mod_consts.const_str_plain_scale);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_plain_scale);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_swap_sum", mod_consts.const_str_plain_swap_sum);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_str_plain_swap_sum);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_absval", mod_consts.const_str_plain_absval);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_str_plain_absval);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_2a2068285e6d366f221865fe9ac1f835", mod_consts.const_str_digest_2a2068285e6d366f221865fe9ac1f835);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_str_digest_2a2068285e6d366f221865fe9ac1f835);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52", mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_r_tuple", mod_consts.const_tuple_str_plain_n_str_plain_r_tuple);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_r_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple", mod_consts.const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
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
void checkModuleConstants_multi(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_2", mod_consts.const_int_pos_2);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_int_pos_2) && "mod_consts.const_int_pos_2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b", mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b) && "mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_stats", mod_consts.const_str_plain_stats);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_str_plain_stats) && "mod_consts.const_str_plain_stats");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12", mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12) && "mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_scale", mod_consts.const_str_plain_scale);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_plain_scale) && "mod_consts.const_str_plain_scale");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_swap_sum", mod_consts.const_str_plain_swap_sum);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_str_plain_swap_sum) && "mod_consts.const_str_plain_swap_sum");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904) && "mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_absval", mod_consts.const_str_plain_absval);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_str_plain_absval) && "mod_consts.const_str_plain_absval");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_2a2068285e6d366f221865fe9ac1f835", mod_consts.const_str_digest_2a2068285e6d366f221865fe9ac1f835);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_str_digest_2a2068285e6d366f221865fe9ac1f835) && "mod_consts.const_str_digest_2a2068285e6d366f221865fe9ac1f835");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52", mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52) && "mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_r_tuple", mod_consts.const_tuple_str_plain_n_str_plain_r_tuple);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_r_tuple) && "mod_consts.const_tuple_str_plain_n_str_plain_r_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple", mod_consts.const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple) && "mod_consts.const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple) && "mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple) && "mod_consts.const_tuple_str_plain_a_str_plain_b_tuple");
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
static PyObject *module_var_accessor_multi$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_multi->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_multi->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_multi->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_e9ed126aae7656217512eacfdc0c42c3;
static PyCodeObject *code_objects_c74423eab93ad7849166d085b749c664;
static PyCodeObject *code_objects_fccda0fc9ec57ac6ee5f557d706b8114;
static PyCodeObject *code_objects_9babe9bff6707625f25da0a4fc472267;
static PyCodeObject *code_objects_fd3bacaeb8077f3433c269ee63cb9ae2;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_2a2068285e6d366f221865fe9ac1f835); CHECK_OBJECT(module_filename_obj);
code_objects_e9ed126aae7656217512eacfdc0c42c3 = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52, mod_consts.const_str_digest_74782ef1bf586a005b6e6892d14fdc52, NULL, NULL, 0, 0, 0);
code_objects_c74423eab93ad7849166d085b749c664 = MAKE_CODE_OBJECT(module_filename_obj, 18, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_absval, mod_consts.const_str_plain_absval, mod_consts.const_tuple_str_plain_n_str_plain_r_tuple, NULL, 1, 0, 0);
code_objects_fccda0fc9ec57ac6ee5f557d706b8114 = MAKE_CODE_OBJECT(module_filename_obj, 7, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_scale, mod_consts.const_str_plain_scale, mod_consts.const_tuple_str_plain_x_str_plain_y_str_plain_z_tuple, NULL, 1, 0, 0);
code_objects_9babe9bff6707625f25da0a4fc472267 = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_stats, mod_consts.const_str_plain_stats, mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_total_str_plain_diff_tuple, NULL, 2, 0, 0);
code_objects_fd3bacaeb8077f3433c269ee63cb9ae2 = MAKE_CODE_OBJECT(module_filename_obj, 13, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_swap_sum, mod_consts.const_str_plain_swap_sum, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple, NULL, 2, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION_multi$$$function__1_stats(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_multi$$$function__2_scale(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_multi$$$function__3_swap_sum(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_multi$$$function__4_absval(PyThreadState *tstate, PyObject *annotations);


// The module function definitions.
static PyObject *impl_multi$$$function__1_stats(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
PyObject *var_total = NULL;
PyObject *var_diff = NULL;
struct Nuitka_FrameObject *frame_frame_multi$$$function__1_stats;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
PyObject *tmp_return_value = NULL;
static struct Nuitka_FrameObject *cache_frame_frame_multi$$$function__1_stats = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;

    // Actual function body.
// Tried code:
if (isFrameUnusable(cache_frame_frame_multi$$$function__1_stats)) {
    Py_XDECREF(cache_frame_frame_multi$$$function__1_stats);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_multi$$$function__1_stats == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_multi$$$function__1_stats = MAKE_FUNCTION_FRAME(tstate, code_objects_9babe9bff6707625f25da0a4fc472267, module_multi, sizeof(void *)+sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_multi$$$function__1_stats->m_type_description == NULL);
frame_frame_multi$$$function__1_stats = cache_frame_frame_multi$$$function__1_stats;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_multi$$$function__1_stats);
assert(Py_REFCNT(frame_frame_multi$$$function__1_stats) == 2);

// Framed code:
{
PyObject *tmp_assign_source_1;
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
CHECK_OBJECT(par_a);
tmp_add_expr_left_1 = par_a;
CHECK_OBJECT(par_b);
tmp_add_expr_right_1 = par_b;
tmp_assign_source_1 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_assign_source_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = var_total;
    var_total = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_2;
PyObject *tmp_sub_expr_left_1;
PyObject *tmp_sub_expr_right_1;
CHECK_OBJECT(par_a);
tmp_sub_expr_left_1 = par_a;
CHECK_OBJECT(par_b);
tmp_sub_expr_right_1 = par_b;
tmp_assign_source_2 = BINARY_OPERATION_SUB_OBJECT_OBJECT_OBJECT(tmp_sub_expr_left_1, tmp_sub_expr_right_1);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 3;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = var_diff;
    var_diff = tmp_assign_source_2;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_add_expr_left_2;
PyObject *tmp_add_expr_right_2;
CHECK_OBJECT(var_total);
tmp_add_expr_left_2 = var_total;
CHECK_OBJECT(var_diff);
tmp_add_expr_right_2 = var_diff;
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_2, tmp_add_expr_right_2);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 4;
type_description_1 = "oooo";
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
        exception_tb = MAKE_TRACEBACK(frame_frame_multi$$$function__1_stats, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_multi$$$function__1_stats->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_multi$$$function__1_stats, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_multi$$$function__1_stats,
    type_description_1,
    par_a,
    par_b,
    var_total,
    var_diff
);


// Release cached frame if used for exception.
if (frame_frame_multi$$$function__1_stats == cache_frame_frame_multi$$$function__1_stats) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_multi$$$function__1_stats);
    cache_frame_frame_multi$$$function__1_stats = NULL;
}

assertFrameObject(frame_frame_multi$$$function__1_stats);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
CHECK_OBJECT(var_total);
CHECK_OBJECT(var_total);
Py_DECREF(var_total);
var_total = NULL;
CHECK_OBJECT(var_diff);
CHECK_OBJECT(var_diff);
Py_DECREF(var_diff);
var_diff = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_total);
var_total = NULL;
Py_XDECREF(var_diff);
var_diff = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto function_exception_exit;
// End of try:

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


static PyObject *impl_multi$$$function__2_scale(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_x = python_pars[0];
PyObject *var_y = NULL;
PyObject *var_z = NULL;
struct Nuitka_FrameObject *frame_frame_multi$$$function__2_scale;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_multi$$$function__2_scale = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;

    // Actual function body.
// Tried code:
if (isFrameUnusable(cache_frame_frame_multi$$$function__2_scale)) {
    Py_XDECREF(cache_frame_frame_multi$$$function__2_scale);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_multi$$$function__2_scale == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_multi$$$function__2_scale = MAKE_FUNCTION_FRAME(tstate, code_objects_fccda0fc9ec57ac6ee5f557d706b8114, module_multi, sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_multi$$$function__2_scale->m_type_description == NULL);
frame_frame_multi$$$function__2_scale = cache_frame_frame_multi$$$function__2_scale;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_multi$$$function__2_scale);
assert(Py_REFCNT(frame_frame_multi$$$function__2_scale) == 2);

// Framed code:
{
PyObject *tmp_assign_source_1;
PyObject *tmp_mult_expr_left_1;
PyObject *tmp_mult_expr_right_1;
CHECK_OBJECT(par_x);
tmp_mult_expr_left_1 = par_x;
tmp_mult_expr_right_1 = mod_consts.const_int_pos_2;
tmp_assign_source_1 = BINARY_OPERATION_MULT_OBJECT_OBJECT_LONG(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
if (tmp_assign_source_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 8;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = var_y;
    var_y = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
{
PyObject *tmp_assign_source_2;
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
CHECK_OBJECT(var_y);
tmp_add_expr_left_1 = var_y;
tmp_add_expr_right_1 = const_int_pos_1;
tmp_assign_source_2 = BINARY_OPERATION_ADD_OBJECT_OBJECT_LONG(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 9;
type_description_1 = "ooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = var_z;
    var_z = tmp_assign_source_2;
    Py_XDECREF(old);
}

}


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_multi$$$function__2_scale, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_multi$$$function__2_scale->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_multi$$$function__2_scale, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_multi$$$function__2_scale,
    type_description_1,
    par_x,
    var_y,
    var_z
);


// Release cached frame if used for exception.
if (frame_frame_multi$$$function__2_scale == cache_frame_frame_multi$$$function__2_scale) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_multi$$$function__2_scale);
    cache_frame_frame_multi$$$function__2_scale = NULL;
}

assertFrameObject(frame_frame_multi$$$function__2_scale);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
CHECK_OBJECT(var_z);
tmp_return_value = var_z;
Py_INCREF(tmp_return_value);
goto try_return_handler_1;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
CHECK_OBJECT(var_y);
CHECK_OBJECT(var_y);
Py_DECREF(var_y);
var_y = NULL;
CHECK_OBJECT(var_z);
CHECK_OBJECT(var_z);
Py_DECREF(var_z);
var_z = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(var_y);
var_y = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto function_exception_exit;
// End of try:

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


static PyObject *impl_multi$$$function__3_swap_sum(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
PyObject *tmp_tuple_unpack_1__element_1 = NULL;
PyObject *tmp_tuple_unpack_1__element_2 = NULL;
PyObject *tmp_tuple_unpack_1__source_iter = NULL;
struct Nuitka_FrameObject *frame_frame_multi$$$function__3_swap_sum;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_2;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_2;
PyObject *tmp_return_value = NULL;
static struct Nuitka_FrameObject *cache_frame_frame_multi$$$function__3_swap_sum = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_3;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_3;

    // Actual function body.
{
PyObject *tmp_assign_source_1;
PyObject *tmp_iter_arg_1;
PyObject *tmp_tuple_element_1;
CHECK_OBJECT(par_b);
tmp_tuple_element_1 = par_b;
tmp_iter_arg_1 = MAKE_TUPLE_EMPTY(tstate, 2);
PyTuple_SET_ITEM0(tmp_iter_arg_1, 0, tmp_tuple_element_1);
CHECK_OBJECT(par_a);
tmp_tuple_element_1 = par_a;
PyTuple_SET_ITEM0(tmp_iter_arg_1, 1, tmp_tuple_element_1);
tmp_assign_source_1 = MAKE_ITERATOR_INFALLIBLE(tmp_iter_arg_1);
CHECK_OBJECT(tmp_iter_arg_1);
Py_DECREF(tmp_iter_arg_1);
assert(!(tmp_assign_source_1 == NULL));
{
    PyObject *old = tmp_tuple_unpack_1__source_iter;
    tmp_tuple_unpack_1__source_iter = tmp_assign_source_1;
    Py_XDECREF(old);
}

}
// Tried code:
if (isFrameUnusable(cache_frame_frame_multi$$$function__3_swap_sum)) {
    Py_XDECREF(cache_frame_frame_multi$$$function__3_swap_sum);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_multi$$$function__3_swap_sum == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_multi$$$function__3_swap_sum = MAKE_FUNCTION_FRAME(tstate, code_objects_fd3bacaeb8077f3433c269ee63cb9ae2, module_multi, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_multi$$$function__3_swap_sum->m_type_description == NULL);
frame_frame_multi$$$function__3_swap_sum = cache_frame_frame_multi$$$function__3_swap_sum;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_multi$$$function__3_swap_sum);
assert(Py_REFCNT(frame_frame_multi$$$function__3_swap_sum) == 2);

// Framed code:
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



exception_lineno = 14;
type_description_1 = "oo";
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



exception_lineno = 14;
type_description_1 = "oo";
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



exception_lineno = 14;
type_description_1 = "oo";
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
    PyObject *old = par_a;
    assert(old != NULL);
    par_a = tmp_assign_source_4;
    Py_INCREF(par_a);
    Py_DECREF(old);
}

}
Py_XDECREF(tmp_tuple_unpack_1__element_1);
tmp_tuple_unpack_1__element_1 = NULL;

{
PyObject *tmp_assign_source_5;
CHECK_OBJECT(tmp_tuple_unpack_1__element_2);
tmp_assign_source_5 = tmp_tuple_unpack_1__element_2;
{
    PyObject *old = par_b;
    assert(old != NULL);
    par_b = tmp_assign_source_5;
    Py_INCREF(par_b);
    Py_DECREF(old);
}

}
Py_XDECREF(tmp_tuple_unpack_1__element_2);
tmp_tuple_unpack_1__element_2 = NULL;

{
PyObject *tmp_sub_expr_left_1;
PyObject *tmp_sub_expr_right_1;
CHECK_OBJECT(par_a);
tmp_sub_expr_left_1 = par_a;
CHECK_OBJECT(par_b);
tmp_sub_expr_right_1 = par_b;
tmp_return_value = BINARY_OPERATION_SUB_OBJECT_OBJECT_OBJECT(tmp_sub_expr_left_1, tmp_sub_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 15;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_multi$$$function__3_swap_sum, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_multi$$$function__3_swap_sum->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_multi$$$function__3_swap_sum, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_multi$$$function__3_swap_sum,
    type_description_1,
    par_a,
    par_b
);


// Release cached frame if used for exception.
if (frame_frame_multi$$$function__3_swap_sum == cache_frame_frame_multi$$$function__3_swap_sum) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_multi$$$function__3_swap_sum);
    cache_frame_frame_multi$$$function__3_swap_sum = NULL;
}

assertFrameObject(frame_frame_multi$$$function__3_swap_sum);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
CHECK_OBJECT(par_a);
CHECK_OBJECT(par_a);
Py_DECREF(par_a);
par_a = NULL;
CHECK_OBJECT(par_b);
CHECK_OBJECT(par_b);
Py_DECREF(par_b);
par_b = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_3 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_3 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(par_a);
par_a = NULL;
Py_XDECREF(par_b);
par_b = NULL;
// Re-raise.
exception_state = exception_keeper_name_3;
exception_lineno = exception_keeper_lineno_3;

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


static PyObject *impl_multi$$$function__4_absval(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_n = python_pars[0];
PyObject *var_r = NULL;
struct Nuitka_FrameObject *frame_frame_multi$$$function__4_absval;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_multi$$$function__4_absval = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;

    // Actual function body.
{
PyObject *tmp_assign_source_1;
CHECK_OBJECT(par_n);
tmp_assign_source_1 = par_n;
{
    PyObject *old = var_r;
    var_r = tmp_assign_source_1;
    Py_INCREF(var_r);
    Py_XDECREF(old);
}

}
// Tried code:
if (isFrameUnusable(cache_frame_frame_multi$$$function__4_absval)) {
    Py_XDECREF(cache_frame_frame_multi$$$function__4_absval);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_multi$$$function__4_absval == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_multi$$$function__4_absval = MAKE_FUNCTION_FRAME(tstate, code_objects_c74423eab93ad7849166d085b749c664, module_multi, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_multi$$$function__4_absval->m_type_description == NULL);
frame_frame_multi$$$function__4_absval = cache_frame_frame_multi$$$function__4_absval;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_multi$$$function__4_absval);
assert(Py_REFCNT(frame_frame_multi$$$function__4_absval) == 2);

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


exception_lineno = 20;
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
PyObject *tmp_assign_source_2;
PyObject *tmp_operand_value_1;
CHECK_OBJECT(par_n);
tmp_operand_value_1 = par_n;
tmp_assign_source_2 = UNARY_OPERATION(PyNumber_Negative, tmp_operand_value_1);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 21;
type_description_1 = "oo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = var_r;
    assert(old != NULL);
    var_r = tmp_assign_source_2;
    Py_DECREF(old);
}

}
branch_no_1:;


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_multi$$$function__4_absval, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_multi$$$function__4_absval->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_multi$$$function__4_absval, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_multi$$$function__4_absval,
    type_description_1,
    par_n,
    var_r
);


// Release cached frame if used for exception.
if (frame_frame_multi$$$function__4_absval == cache_frame_frame_multi$$$function__4_absval) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_multi$$$function__4_absval);
    cache_frame_frame_multi$$$function__4_absval = NULL;
}

assertFrameObject(frame_frame_multi$$$function__4_absval);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto try_except_handler_1;
frame_no_exception_1:;
CHECK_OBJECT(var_r);
tmp_return_value = var_r;
Py_INCREF(tmp_return_value);
goto try_return_handler_1;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;
// Return handler code:
try_return_handler_1:;
CHECK_OBJECT(var_r);
CHECK_OBJECT(var_r);
Py_DECREF(var_r);
var_r = NULL;
goto function_return_exit;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(var_r);
CHECK_OBJECT(var_r);
Py_DECREF(var_r);
var_r = NULL;
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



static PyObject *MAKE_FUNCTION_multi$$$function__1_stats(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_multi$$$function__1_stats,
        mod_consts.const_str_plain_stats,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_9babe9bff6707625f25da0a4fc472267,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_multi,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_multi$$$function__2_scale(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_multi$$$function__2_scale,
        mod_consts.const_str_plain_scale,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_fccda0fc9ec57ac6ee5f557d706b8114,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_multi,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_multi$$$function__3_swap_sum(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_multi$$$function__3_swap_sum,
        mod_consts.const_str_plain_swap_sum,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_fd3bacaeb8077f3433c269ee63cb9ae2,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_multi,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_multi$$$function__4_absval(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_multi$$$function__4_absval,
        mod_consts.const_str_plain_absval,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_c74423eab93ad7849166d085b749c664,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_multi,
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

static function_impl_code const function_table_multi[] = {
impl_multi$$$function__1_stats,
impl_multi$$$function__2_scale,
impl_multi$$$function__3_swap_sum,
impl_multi$$$function__4_absval,
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

    return Nuitka_Function_GetFunctionState(function, function_table_multi);
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
        module_multi,
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
        function_table_multi,
        sizeof(function_table_multi) / sizeof(function_impl_code)
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
static char const *module_full_name = "multi";
#endif

// Internal entry point for module code.
PyObject *module_code_multi(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("multi");

    // Store the module for future use.
    module_multi = module;

    moduledict_multi = MODULE_DICT(module_multi);

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
        PRINT_STRING("multi: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("multi: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("multi: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "multi" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initmulti\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict_multi,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_multi,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_multi,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_multi,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_multi,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_multi);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_multi, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_multi, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_multi, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_multi);
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

        UPDATE_STRING_DICT1(moduledict_multi, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_multi;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_multi, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_multi, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_multi = MAKE_MODULE_FRAME(code_objects_e9ed126aae7656217512eacfdc0c42c3, module_multi);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_multi);
assert(Py_REFCNT(frame_frame_multi) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_multi$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_multi$__spec__(tstate);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_multi, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_multi->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_multi, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_multi);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict_multi, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_multi, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_annotations_1;
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);

tmp_assign_source_5 = MAKE_FUNCTION_multi$$$function__1_stats(tstate, tmp_annotations_1);

UPDATE_STRING_DICT1(moduledict_multi, (Nuitka_StringObject *)mod_consts.const_str_plain_stats, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
PyObject *tmp_annotations_2;
tmp_annotations_2 = DICT_COPY(tstate, mod_consts.const_dict_0a6b9e1ea4f76ea6a71621d0f77d3d12);

tmp_assign_source_6 = MAKE_FUNCTION_multi$$$function__2_scale(tstate, tmp_annotations_2);

UPDATE_STRING_DICT1(moduledict_multi, (Nuitka_StringObject *)mod_consts.const_str_plain_scale, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;
PyObject *tmp_annotations_3;
tmp_annotations_3 = DICT_COPY(tstate, mod_consts.const_dict_a651edb4508386ac796e5d15189d2d4b);

tmp_assign_source_7 = MAKE_FUNCTION_multi$$$function__3_swap_sum(tstate, tmp_annotations_3);

UPDATE_STRING_DICT1(moduledict_multi, (Nuitka_StringObject *)mod_consts.const_str_plain_swap_sum, tmp_assign_source_7);
}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_annotations_4;
tmp_annotations_4 = DICT_COPY(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);

tmp_assign_source_8 = MAKE_FUNCTION_multi$$$function__4_absval(tstate, tmp_annotations_4);

UPDATE_STRING_DICT1(moduledict_multi, (Nuitka_StringObject *)mod_consts.const_str_plain_absval, tmp_assign_source_8);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("multi", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "multi" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_multi);
    return module_multi;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_multi, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("multi", false);

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
            moduledict_multi,
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
static struct PyModuleDef mdef_multi = {
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
            moduledict_multi,
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

static PyObject *PyInit_multi_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_multi(tstate, module, getLoaderEntry("multi"));

#if PYTHON_VERSION < 0x300
    // Our "__file__" value will not be respected by CPython and one
    // way we can avoid it, is by having a capsule type, that when
    // it gets released, we are called and repair the value.

    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_multi, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_multi,
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

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_multi, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_multi_slot(PyObject *module) {
    PyObject *result = PyInit_multi_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_multi)(void) {
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
    mdef_multi.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_multi);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_multi_slot},
        {0, NULL}
    };

    mdef_multi.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_multi);
#elif PYTHON_VERSION >= 0x300
    return PyInit_multi_phase2(module);
#else
    PyInit_multi_phase2(module);
#endif
}
