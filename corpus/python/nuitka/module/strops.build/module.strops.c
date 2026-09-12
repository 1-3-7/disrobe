/* Generated code for Python module 'strops'
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



/* The "module_strops" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_strops;
PyDictObject *moduledict_strops;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_str_chr_33;
PyObject *const_str_chr_61;
PyObject *const_str_plain_upper;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_dict_f12d39973b0594a0adb574dbe1e8f5f7;
PyObject *const_str_plain_shout;
PyObject *const_dict_d04b46eddb3667b328558bd5c3995fde;
PyObject *const_str_plain_label;
PyObject *const_dict_da1a137dc1d1b1d9e777330c00a272a2;
PyObject *const_str_plain_repeat;
PyObject *const_str_digest_59c7161a40b464b871849307f74cb963;
PyObject *const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a;
PyObject *const_tuple_str_plain_name_str_plain_value_tuple;
PyObject *const_tuple_str_plain_s_str_plain_n_tuple;
PyObject *const_tuple_str_plain_s_tuple;
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
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("strops"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 16) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 16 values, got %d\n",
                    UN_TRANSLATE("strops"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_chr_33", mod_consts.const_str_chr_33);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_str_chr_33);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_chr_61", mod_consts.const_str_chr_61);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_chr_61);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_upper", mod_consts.const_str_plain_upper);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_str_plain_upper);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7", mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_shout", mod_consts.const_str_plain_shout);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_plain_shout);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_d04b46eddb3667b328558bd5c3995fde", mod_consts.const_dict_d04b46eddb3667b328558bd5c3995fde);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_dict_d04b46eddb3667b328558bd5c3995fde);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_label", mod_consts.const_str_plain_label);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_str_plain_label);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_da1a137dc1d1b1d9e777330c00a272a2", mod_consts.const_dict_da1a137dc1d1b1d9e777330c00a272a2);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_dict_da1a137dc1d1b1d9e777330c00a272a2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_repeat", mod_consts.const_str_plain_repeat);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_str_plain_repeat);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_59c7161a40b464b871849307f74cb963", mod_consts.const_str_digest_59c7161a40b464b871849307f74cb963);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_str_digest_59c7161a40b464b871849307f74cb963);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a", mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_name_str_plain_value_tuple", mod_consts.const_tuple_str_plain_name_str_plain_value_tuple);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_name_str_plain_value_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_s_str_plain_n_tuple", mod_consts.const_tuple_str_plain_s_str_plain_n_tuple);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_s_str_plain_n_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_s_tuple", mod_consts.const_tuple_str_plain_s_tuple);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_s_tuple);
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
void checkModuleConstants_strops(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_chr_33", mod_consts.const_str_chr_33);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_str_chr_33) && "mod_consts.const_str_chr_33");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_chr_61", mod_consts.const_str_chr_61);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_chr_61) && "mod_consts.const_str_chr_61");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_upper", mod_consts.const_str_plain_upper);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_str_plain_upper) && "mod_consts.const_str_plain_upper");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7", mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7) && "mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_shout", mod_consts.const_str_plain_shout);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_plain_shout) && "mod_consts.const_str_plain_shout");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_d04b46eddb3667b328558bd5c3995fde", mod_consts.const_dict_d04b46eddb3667b328558bd5c3995fde);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_dict_d04b46eddb3667b328558bd5c3995fde) && "mod_consts.const_dict_d04b46eddb3667b328558bd5c3995fde");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_label", mod_consts.const_str_plain_label);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_str_plain_label) && "mod_consts.const_str_plain_label");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_da1a137dc1d1b1d9e777330c00a272a2", mod_consts.const_dict_da1a137dc1d1b1d9e777330c00a272a2);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_dict_da1a137dc1d1b1d9e777330c00a272a2) && "mod_consts.const_dict_da1a137dc1d1b1d9e777330c00a272a2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_repeat", mod_consts.const_str_plain_repeat);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_str_plain_repeat) && "mod_consts.const_str_plain_repeat");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_59c7161a40b464b871849307f74cb963", mod_consts.const_str_digest_59c7161a40b464b871849307f74cb963);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_str_digest_59c7161a40b464b871849307f74cb963) && "mod_consts.const_str_digest_59c7161a40b464b871849307f74cb963");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a", mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a) && "mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_name_str_plain_value_tuple", mod_consts.const_tuple_str_plain_name_str_plain_value_tuple);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_name_str_plain_value_tuple) && "mod_consts.const_tuple_str_plain_name_str_plain_value_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_s_str_plain_n_tuple", mod_consts.const_tuple_str_plain_s_str_plain_n_tuple);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_s_str_plain_n_tuple) && "mod_consts.const_tuple_str_plain_s_str_plain_n_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_s_tuple", mod_consts.const_tuple_str_plain_s_tuple);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_s_tuple) && "mod_consts.const_tuple_str_plain_s_tuple");
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
static PyObject *module_var_accessor_strops$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_strops->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_strops->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_strops->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_427604645862916fbf036cdd245706dc;
static PyCodeObject *code_objects_1d161ef1cbfe26b6a5f307840d9e75f5;
static PyCodeObject *code_objects_0bd9d74d74038da64c9b1dddc760eacd;
static PyCodeObject *code_objects_ca939545160b7f6f508a01affc4915be;
static PyCodeObject *code_objects_93ef315ccc4e106ad51bfac33e41c1b5;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_59c7161a40b464b871849307f74cb963); CHECK_OBJECT(module_filename_obj);
code_objects_427604645862916fbf036cdd245706dc = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a, mod_consts.const_str_digest_cbb070a3ca804aa2c89902a4b554cb6a, NULL, NULL, 0, 0, 0);
code_objects_1d161ef1cbfe26b6a5f307840d9e75f5 = MAKE_CODE_OBJECT(module_filename_obj, 5, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_label, mod_consts.const_str_plain_label, mod_consts.const_tuple_str_plain_name_str_plain_value_tuple, NULL, 2, 0, 0);
code_objects_0bd9d74d74038da64c9b1dddc760eacd = MAKE_CODE_OBJECT(module_filename_obj, 13, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_repeat, mod_consts.const_str_plain_repeat, mod_consts.const_tuple_str_plain_s_str_plain_n_tuple, NULL, 2, 0, 0);
code_objects_ca939545160b7f6f508a01affc4915be = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_shout, mod_consts.const_str_plain_shout, mod_consts.const_tuple_str_plain_s_tuple, NULL, 1, 0, 0);
code_objects_93ef315ccc4e106ad51bfac33e41c1b5 = MAKE_CODE_OBJECT(module_filename_obj, 9, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_upper, mod_consts.const_str_plain_upper, mod_consts.const_tuple_str_plain_s_tuple, NULL, 1, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION_strops$$$function__1_shout(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_strops$$$function__2_label(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_strops$$$function__3_upper(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_strops$$$function__4_repeat(PyThreadState *tstate, PyObject *annotations);


// The module function definitions.
static PyObject *impl_strops$$$function__1_shout(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_s = python_pars[0];
struct Nuitka_FrameObject *frame_frame_strops$$$function__1_shout;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_strops$$$function__1_shout = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_strops$$$function__1_shout)) {
    Py_XDECREF(cache_frame_frame_strops$$$function__1_shout);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_strops$$$function__1_shout == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_strops$$$function__1_shout = MAKE_FUNCTION_FRAME(tstate, code_objects_ca939545160b7f6f508a01affc4915be, module_strops, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_strops$$$function__1_shout->m_type_description == NULL);
frame_frame_strops$$$function__1_shout = cache_frame_frame_strops$$$function__1_shout;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_strops$$$function__1_shout);
assert(Py_REFCNT(frame_frame_strops$$$function__1_shout) == 2);

// Framed code:
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
CHECK_OBJECT(par_s);
tmp_add_expr_left_1 = par_s;
tmp_add_expr_right_1 = mod_consts.const_str_chr_33;
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_UNICODE(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_strops$$$function__1_shout, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_strops$$$function__1_shout->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_strops$$$function__1_shout, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_strops$$$function__1_shout,
    type_description_1,
    par_s
);


// Release cached frame if used for exception.
if (frame_frame_strops$$$function__1_shout == cache_frame_frame_strops$$$function__1_shout) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_strops$$$function__1_shout);
    cache_frame_frame_strops$$$function__1_shout = NULL;
}

assertFrameObject(frame_frame_strops$$$function__1_shout);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_s);
Py_DECREF(par_s);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_s);
Py_DECREF(par_s);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_strops$$$function__2_label(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_name = python_pars[0];
PyObject *par_value = python_pars[1];
struct Nuitka_FrameObject *frame_frame_strops$$$function__2_label;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_strops$$$function__2_label = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_strops$$$function__2_label)) {
    Py_XDECREF(cache_frame_frame_strops$$$function__2_label);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_strops$$$function__2_label == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_strops$$$function__2_label = MAKE_FUNCTION_FRAME(tstate, code_objects_1d161ef1cbfe26b6a5f307840d9e75f5, module_strops, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_strops$$$function__2_label->m_type_description == NULL);
frame_frame_strops$$$function__2_label = cache_frame_frame_strops$$$function__2_label;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_strops$$$function__2_label);
assert(Py_REFCNT(frame_frame_strops$$$function__2_label) == 2);

// Framed code:
{
PyObject *tmp_string_concat_values_1;
PyObject *tmp_tuple_element_1;
PyObject *tmp_format_value_1;
PyObject *tmp_format_spec_1;
CHECK_OBJECT(par_name);
tmp_format_value_1 = par_name;
tmp_format_spec_1 = const_str_empty;
tmp_tuple_element_1 = BUILTIN_FORMAT(tstate, tmp_format_value_1, tmp_format_spec_1);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 6;
type_description_1 = "oo";
    goto frame_exception_exit_1;
}
tmp_string_concat_values_1 = MAKE_TUPLE_EMPTY(tstate, 3);
{
PyObject *tmp_format_value_2;
PyObject *tmp_format_spec_2;
PyTuple_SET_ITEM(tmp_string_concat_values_1, 0, tmp_tuple_element_1);
tmp_tuple_element_1 = mod_consts.const_str_chr_61;
PyTuple_SET_ITEM0(tmp_string_concat_values_1, 1, tmp_tuple_element_1);
CHECK_OBJECT(par_value);
tmp_format_value_2 = par_value;
tmp_format_spec_2 = const_str_empty;
tmp_tuple_element_1 = BUILTIN_FORMAT(tstate, tmp_format_value_2, tmp_format_spec_2);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 6;
type_description_1 = "oo";
    goto tuple_build_exception_1;
}
PyTuple_SET_ITEM(tmp_string_concat_values_1, 2, tmp_tuple_element_1);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_strops$$$function__2_label, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_strops$$$function__2_label->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_strops$$$function__2_label, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_strops$$$function__2_label,
    type_description_1,
    par_name,
    par_value
);


// Release cached frame if used for exception.
if (frame_frame_strops$$$function__2_label == cache_frame_frame_strops$$$function__2_label) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_strops$$$function__2_label);
    cache_frame_frame_strops$$$function__2_label = NULL;
}

assertFrameObject(frame_frame_strops$$$function__2_label);

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
CHECK_OBJECT(par_value);
Py_DECREF(par_value);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_name);
Py_DECREF(par_name);
CHECK_OBJECT(par_value);
Py_DECREF(par_value);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_strops$$$function__3_upper(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_s = python_pars[0];
struct Nuitka_FrameObject *frame_frame_strops$$$function__3_upper;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_strops$$$function__3_upper = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_strops$$$function__3_upper)) {
    Py_XDECREF(cache_frame_frame_strops$$$function__3_upper);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_strops$$$function__3_upper == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_strops$$$function__3_upper = MAKE_FUNCTION_FRAME(tstate, code_objects_93ef315ccc4e106ad51bfac33e41c1b5, module_strops, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_strops$$$function__3_upper->m_type_description == NULL);
frame_frame_strops$$$function__3_upper = cache_frame_frame_strops$$$function__3_upper;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_strops$$$function__3_upper);
assert(Py_REFCNT(frame_frame_strops$$$function__3_upper) == 2);

// Framed code:
{
PyObject *tmp_called_value_1;
PyObject *tmp_expression_value_1;
CHECK_OBJECT(par_s);
tmp_expression_value_1 = par_s;
tmp_called_value_1 = LOOKUP_ATTRIBUTE(tstate, tmp_expression_value_1, mod_consts.const_str_plain_upper);
if (tmp_called_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 10;
type_description_1 = "o";
    goto frame_exception_exit_1;
}
frame_frame_strops$$$function__3_upper->m_frame.f_lineno = 10;
tmp_return_value = CALL_FUNCTION_NO_ARGS(tstate, tmp_called_value_1);
CHECK_OBJECT(tmp_called_value_1);
Py_DECREF(tmp_called_value_1);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_strops$$$function__3_upper, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_strops$$$function__3_upper->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_strops$$$function__3_upper, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_strops$$$function__3_upper,
    type_description_1,
    par_s
);


// Release cached frame if used for exception.
if (frame_frame_strops$$$function__3_upper == cache_frame_frame_strops$$$function__3_upper) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_strops$$$function__3_upper);
    cache_frame_frame_strops$$$function__3_upper = NULL;
}

assertFrameObject(frame_frame_strops$$$function__3_upper);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_s);
Py_DECREF(par_s);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_s);
Py_DECREF(par_s);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_strops$$$function__4_repeat(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_s = python_pars[0];
PyObject *par_n = python_pars[1];
struct Nuitka_FrameObject *frame_frame_strops$$$function__4_repeat;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_strops$$$function__4_repeat = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_strops$$$function__4_repeat)) {
    Py_XDECREF(cache_frame_frame_strops$$$function__4_repeat);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_strops$$$function__4_repeat == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_strops$$$function__4_repeat = MAKE_FUNCTION_FRAME(tstate, code_objects_0bd9d74d74038da64c9b1dddc760eacd, module_strops, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_strops$$$function__4_repeat->m_type_description == NULL);
frame_frame_strops$$$function__4_repeat = cache_frame_frame_strops$$$function__4_repeat;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_strops$$$function__4_repeat);
assert(Py_REFCNT(frame_frame_strops$$$function__4_repeat) == 2);

// Framed code:
{
PyObject *tmp_mult_expr_left_1;
PyObject *tmp_mult_expr_right_1;
CHECK_OBJECT(par_s);
tmp_mult_expr_left_1 = par_s;
CHECK_OBJECT(par_n);
tmp_mult_expr_right_1 = par_n;
tmp_return_value = BINARY_OPERATION_MULT_OBJECT_OBJECT_OBJECT(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
if (tmp_return_value == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 14;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_strops$$$function__4_repeat, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_strops$$$function__4_repeat->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_strops$$$function__4_repeat, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_strops$$$function__4_repeat,
    type_description_1,
    par_s,
    par_n
);


// Release cached frame if used for exception.
if (frame_frame_strops$$$function__4_repeat == cache_frame_frame_strops$$$function__4_repeat) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_strops$$$function__4_repeat);
    cache_frame_frame_strops$$$function__4_repeat = NULL;
}

assertFrameObject(frame_frame_strops$$$function__4_repeat);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_s);
Py_DECREF(par_s);
CHECK_OBJECT(par_n);
Py_DECREF(par_n);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_s);
Py_DECREF(par_s);
CHECK_OBJECT(par_n);
Py_DECREF(par_n);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}



static PyObject *MAKE_FUNCTION_strops$$$function__1_shout(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_strops$$$function__1_shout,
        mod_consts.const_str_plain_shout,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_ca939545160b7f6f508a01affc4915be,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_strops,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_strops$$$function__2_label(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_strops$$$function__2_label,
        mod_consts.const_str_plain_label,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_1d161ef1cbfe26b6a5f307840d9e75f5,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_strops,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_strops$$$function__3_upper(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_strops$$$function__3_upper,
        mod_consts.const_str_plain_upper,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_93ef315ccc4e106ad51bfac33e41c1b5,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_strops,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_strops$$$function__4_repeat(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_strops$$$function__4_repeat,
        mod_consts.const_str_plain_repeat,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_0bd9d74d74038da64c9b1dddc760eacd,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_strops,
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

static function_impl_code const function_table_strops[] = {
impl_strops$$$function__1_shout,
impl_strops$$$function__2_label,
impl_strops$$$function__3_upper,
impl_strops$$$function__4_repeat,
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

    return Nuitka_Function_GetFunctionState(function, function_table_strops);
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
        module_strops,
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
        function_table_strops,
        sizeof(function_table_strops) / sizeof(function_impl_code)
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
static char const *module_full_name = "strops";
#endif

// Internal entry point for module code.
PyObject *module_code_strops(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("strops");

    // Store the module for future use.
    module_strops = module;

    moduledict_strops = MODULE_DICT(module_strops);

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
        PRINT_STRING("strops: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("strops: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("strops: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "strops" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initstrops\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict_strops,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_strops,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_strops,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_strops,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_strops,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_strops);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_strops, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_strops, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_strops, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_strops);
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

        UPDATE_STRING_DICT1(moduledict_strops, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_strops;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_strops, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_strops, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_strops = MAKE_MODULE_FRAME(code_objects_427604645862916fbf036cdd245706dc, module_strops);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_strops);
assert(Py_REFCNT(frame_frame_strops) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_strops$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_strops$__spec__(tstate);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_strops, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_strops->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_strops, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_strops);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict_strops, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_strops, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_annotations_1;
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7);

tmp_assign_source_5 = MAKE_FUNCTION_strops$$$function__1_shout(tstate, tmp_annotations_1);

UPDATE_STRING_DICT1(moduledict_strops, (Nuitka_StringObject *)mod_consts.const_str_plain_shout, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
PyObject *tmp_annotations_2;
tmp_annotations_2 = DICT_COPY(tstate, mod_consts.const_dict_d04b46eddb3667b328558bd5c3995fde);

tmp_assign_source_6 = MAKE_FUNCTION_strops$$$function__2_label(tstate, tmp_annotations_2);

UPDATE_STRING_DICT1(moduledict_strops, (Nuitka_StringObject *)mod_consts.const_str_plain_label, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;
PyObject *tmp_annotations_3;
tmp_annotations_3 = DICT_COPY(tstate, mod_consts.const_dict_f12d39973b0594a0adb574dbe1e8f5f7);

tmp_assign_source_7 = MAKE_FUNCTION_strops$$$function__3_upper(tstate, tmp_annotations_3);

UPDATE_STRING_DICT1(moduledict_strops, (Nuitka_StringObject *)mod_consts.const_str_plain_upper, tmp_assign_source_7);
}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_annotations_4;
tmp_annotations_4 = DICT_COPY(tstate, mod_consts.const_dict_da1a137dc1d1b1d9e777330c00a272a2);

tmp_assign_source_8 = MAKE_FUNCTION_strops$$$function__4_repeat(tstate, tmp_annotations_4);

UPDATE_STRING_DICT1(moduledict_strops, (Nuitka_StringObject *)mod_consts.const_str_plain_repeat, tmp_assign_source_8);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("strops", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "strops" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_strops);
    return module_strops;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_strops, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("strops", false);

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
            moduledict_strops,
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
static struct PyModuleDef mdef_strops = {
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
            moduledict_strops,
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

static PyObject *PyInit_strops_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_strops(tstate, module, getLoaderEntry("strops"));

#if PYTHON_VERSION < 0x300
    // Our "__file__" value will not be respected by CPython and one
    // way we can avoid it, is by having a capsule type, that when
    // it gets released, we are called and repair the value.

    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_strops, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_strops,
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

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_strops, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_strops_slot(PyObject *module) {
    PyObject *result = PyInit_strops_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_strops)(void) {
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
    mdef_strops.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_strops);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_strops_slot},
        {0, NULL}
    };

    mdef_strops.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_strops);
#elif PYTHON_VERSION >= 0x300
    return PyInit_strops_phase2(module);
#else
    PyInit_strops_phase2(module);
#endif
}
