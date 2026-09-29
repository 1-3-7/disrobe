/* Generated code for Python module 'pkgsurf$tools'
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



/* The "module_pkgsurf$tools" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_pkgsurf$tools;
PyDictObject *moduledict_pkgsurf$tools;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_str_plain_sorted;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_str_plain_gather;
PyObject *const_str_plain_either;
PyObject *const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832;
PyObject *const_str_digest_7f210f8e844e978d1feffc52e02949d9;
PyObject *const_tuple_str_plain_a_str_plain_b_tuple;
PyObject *const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[9];
#endif

static PyObject *module_filename_obj = NULL;

/* Indicator if this modules private constants were created yet. */
static bool constants_created = false;

/* Function to create module private constants. */
static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("pkgsurf.tools"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 9) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 9 values, got %d\n",
                    UN_TRANSLATE("pkgsurf.tools"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_sorted", mod_consts.const_str_plain_sorted);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_str_plain_sorted);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_gather", mod_consts.const_str_plain_gather);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_plain_gather);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_either", mod_consts.const_str_plain_either);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_str_plain_either);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832", mod_consts.const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9", mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple", mod_consts.const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple);
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
void checkModuleConstants_pkgsurf$tools(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_sorted", mod_consts.const_str_plain_sorted);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_str_plain_sorted) && "mod_consts.const_str_plain_sorted");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_gather", mod_consts.const_str_plain_gather);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_plain_gather) && "mod_consts.const_str_plain_gather");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_either", mod_consts.const_str_plain_either);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_str_plain_either) && "mod_consts.const_str_plain_either");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832", mod_consts.const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832) && "mod_consts.const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9", mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9) && "mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_a_str_plain_b_tuple", mod_consts.const_tuple_str_plain_a_str_plain_b_tuple);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple) && "mod_consts.const_tuple_str_plain_a_str_plain_b_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple", mod_consts.const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple) && "mod_consts.const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple");
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
static PyObject *module_var_accessor_pkgsurf$tools$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_pkgsurf$tools->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_pkgsurf$tools->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_pkgsurf$tools->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_b7977cb5d574123fdcec2f0464696b07;
static PyCodeObject *code_objects_443a10bc55617ed4d6debb2d800933ec;
static PyCodeObject *code_objects_8b79483814ac85a8dd9724b775f762d8;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_4a146e53e9ab8120c5d20ac2a3c7a832); CHECK_OBJECT(module_filename_obj);
code_objects_b7977cb5d574123fdcec2f0464696b07 = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9, mod_consts.const_str_digest_7f210f8e844e978d1feffc52e02949d9, NULL, NULL, 0, 0, 0);
code_objects_443a10bc55617ed4d6debb2d800933ec = MAKE_CODE_OBJECT(module_filename_obj, 5, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_either, mod_consts.const_str_plain_either, mod_consts.const_tuple_str_plain_a_str_plain_b_tuple, NULL, 2, 0, 0);
code_objects_8b79483814ac85a8dd9724b775f762d8 = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_OPTIMIZED | CO_NEWLOCALS | CO_VARARGS | CO_VARKEYWORDS, mod_consts.const_str_plain_gather, mod_consts.const_str_plain_gather, mod_consts.const_tuple_str_plain_first_str_plain_args_str_plain_kw_tuple, NULL, 1, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION_pkgsurf$tools$$$function__1_gather(PyThreadState *tstate);


static PyObject *MAKE_FUNCTION_pkgsurf$tools$$$function__2_either(PyThreadState *tstate);


// The module function definitions.
static PyObject *impl_pkgsurf$tools$$$function__1_gather(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_first = python_pars[0];
PyObject *par_args = python_pars[1];
PyObject *par_kw = python_pars[2];
struct Nuitka_FrameObject *frame_frame_pkgsurf$tools$$$function__1_gather;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_pkgsurf$tools$$$function__1_gather = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_pkgsurf$tools$$$function__1_gather)) {
    Py_XDECREF(cache_frame_frame_pkgsurf$tools$$$function__1_gather);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_pkgsurf$tools$$$function__1_gather == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_pkgsurf$tools$$$function__1_gather = MAKE_FUNCTION_FRAME(tstate, code_objects_8b79483814ac85a8dd9724b775f762d8, module_pkgsurf$tools, sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_pkgsurf$tools$$$function__1_gather->m_type_description == NULL);
frame_frame_pkgsurf$tools$$$function__1_gather = cache_frame_frame_pkgsurf$tools$$$function__1_gather;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_pkgsurf$tools$$$function__1_gather);
assert(Py_REFCNT(frame_frame_pkgsurf$tools$$$function__1_gather) == 2);

// Framed code:
{
PyObject *tmp_tuple_element_1;
CHECK_OBJECT(par_first);
tmp_tuple_element_1 = par_first;
tmp_return_value = MAKE_TUPLE_EMPTY(tstate, 3);
{
PyObject *tmp_called_value_1;
PyObject *tmp_args_element_value_1;
PyTuple_SET_ITEM0(tmp_return_value, 0, tmp_tuple_element_1);
CHECK_OBJECT(par_args);
tmp_tuple_element_1 = par_args;
PyTuple_SET_ITEM0(tmp_return_value, 1, tmp_tuple_element_1);
tmp_called_value_1 = LOOKUP_BUILTIN(mod_consts.const_str_plain_sorted);
assert(tmp_called_value_1 != NULL);
CHECK_OBJECT(par_kw);
tmp_args_element_value_1 = par_kw;
frame_frame_pkgsurf$tools$$$function__1_gather->m_frame.f_lineno = 2;
tmp_tuple_element_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_1, tmp_args_element_value_1);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "ooo";
    goto tuple_build_exception_1;
}
PyTuple_SET_ITEM(tmp_return_value, 2, tmp_tuple_element_1);
}
goto tuple_build_no_exception_1;
// Exception handling pass through code for tuple_build:
tuple_build_exception_1:;
Py_DECREF(tmp_return_value);
goto frame_exception_exit_1;
// Finished with no exception for tuple_build:
tuple_build_no_exception_1:;
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
        exception_tb = MAKE_TRACEBACK(frame_frame_pkgsurf$tools$$$function__1_gather, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_pkgsurf$tools$$$function__1_gather->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_pkgsurf$tools$$$function__1_gather, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_pkgsurf$tools$$$function__1_gather,
    type_description_1,
    par_first,
    par_args,
    par_kw
);


// Release cached frame if used for exception.
if (frame_frame_pkgsurf$tools$$$function__1_gather == cache_frame_frame_pkgsurf$tools$$$function__1_gather) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_pkgsurf$tools$$$function__1_gather);
    cache_frame_frame_pkgsurf$tools$$$function__1_gather = NULL;
}

assertFrameObject(frame_frame_pkgsurf$tools$$$function__1_gather);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto function_exception_exit;
frame_no_exception_1:;

NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_first);
Py_DECREF(par_first);
CHECK_OBJECT(par_args);
Py_DECREF(par_args);
CHECK_OBJECT(par_kw);
Py_DECREF(par_kw);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:
   // Function cleanup code if any.
CHECK_OBJECT(par_first);
Py_DECREF(par_first);
CHECK_OBJECT(par_args);
Py_DECREF(par_args);
CHECK_OBJECT(par_kw);
Py_DECREF(par_kw);

   // Actual function exit with return value, making sure we did not make
   // the error status worse despite non-NULL return.
   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_pkgsurf$tools$$$function__2_either(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {
    // Preserve error status for checks
#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif

    // Local variable declarations.
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
struct Nuitka_FrameObject *frame_frame_pkgsurf$tools$$$function__2_either;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_pkgsurf$tools$$$function__2_either = NULL;

    // Actual function body.
if (isFrameUnusable(cache_frame_frame_pkgsurf$tools$$$function__2_either)) {
    Py_XDECREF(cache_frame_frame_pkgsurf$tools$$$function__2_either);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_pkgsurf$tools$$$function__2_either == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_pkgsurf$tools$$$function__2_either = MAKE_FUNCTION_FRAME(tstate, code_objects_443a10bc55617ed4d6debb2d800933ec, module_pkgsurf$tools, sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_pkgsurf$tools$$$function__2_either->m_type_description == NULL);
frame_frame_pkgsurf$tools$$$function__2_either = cache_frame_frame_pkgsurf$tools$$$function__2_either;

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_pkgsurf$tools$$$function__2_either);
assert(Py_REFCNT(frame_frame_pkgsurf$tools$$$function__2_either) == 2);

// Framed code:
{
int tmp_or_left_truth_1;
PyObject *tmp_or_left_value_1;
PyObject *tmp_or_right_value_1;
CHECK_OBJECT(par_a);
tmp_or_left_value_1 = par_a;
tmp_or_left_truth_1 = CHECK_IF_TRUE(tmp_or_left_value_1);
if (tmp_or_left_truth_1 == -1) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 6;
type_description_1 = "oo";
    goto frame_exception_exit_1;
}
if (tmp_or_left_truth_1 == 1) {
    goto or_left_1;
} else {
    goto or_right_1;
}
or_right_1:;
CHECK_OBJECT(par_b);
tmp_or_right_value_1 = par_b;
tmp_return_value = tmp_or_right_value_1;
goto or_end_1;
or_left_1:;
tmp_return_value = tmp_or_left_value_1;
or_end_1:;
Py_INCREF(tmp_return_value);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_pkgsurf$tools$$$function__2_either, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_pkgsurf$tools$$$function__2_either->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_pkgsurf$tools$$$function__2_either, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}

// Attaches locals to frame if any.
Nuitka_Frame_AttachLocals(
    frame_frame_pkgsurf$tools$$$function__2_either,
    type_description_1,
    par_a,
    par_b
);


// Release cached frame if used for exception.
if (frame_frame_pkgsurf$tools$$$function__2_either == cache_frame_frame_pkgsurf$tools$$$function__2_either) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_pkgsurf$tools$$$function__2_either);
    cache_frame_frame_pkgsurf$tools$$$function__2_either = NULL;
}

assertFrameObject(frame_frame_pkgsurf$tools$$$function__2_either);

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



static PyObject *MAKE_FUNCTION_pkgsurf$tools$$$function__1_gather(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_pkgsurf$tools$$$function__1_gather,
        mod_consts.const_str_plain_gather,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_8b79483814ac85a8dd9724b775f762d8,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_pkgsurf$tools,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}



static PyObject *MAKE_FUNCTION_pkgsurf$tools$$$function__2_either(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_pkgsurf$tools$$$function__2_either,
        mod_consts.const_str_plain_either,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_443a10bc55617ed4d6debb2d800933ec,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_pkgsurf$tools,
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

static function_impl_code const function_table_pkgsurf$tools[] = {
impl_pkgsurf$tools$$$function__1_gather,
impl_pkgsurf$tools$$$function__2_either,
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

    return Nuitka_Function_GetFunctionState(function, function_table_pkgsurf$tools);
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
        module_pkgsurf$tools,
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
        function_table_pkgsurf$tools,
        sizeof(function_table_pkgsurf$tools) / sizeof(function_impl_code)
    );
}

static PyMethodDef _method_def_create_compiled_function = {
    "create_compiled_function",
    (PyCFunction)_create_compiled_function,
    METH_VARARGS, NULL
};


#endif

// Actual name might be different when loaded as a package.
#if _NUITKA_MODULE_MODE && 0
static char const *module_full_name = "pkgsurf.tools";
#endif

// Internal entry point for module code.
PyObject *module_code_pkgsurf$tools(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("pkgsurf$tools");

    // Store the module for future use.
    module_pkgsurf$tools = module;

    moduledict_pkgsurf$tools = MODULE_DICT(module_pkgsurf$tools);

    // Modules can be loaded again in case of errors, avoid the init being done again.
    static bool init_done = false;

    if (init_done == false) {
#if _NUITKA_MODULE_MODE && 0
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
        PRINT_STRING("pkgsurf$tools: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("pkgsurf$tools: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("pkgsurf$tools: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 0
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "pkgsurf.tools" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initpkgsurf$tools\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict_pkgsurf$tools,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_pkgsurf$tools,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_pkgsurf$tools,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_pkgsurf$tools,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_pkgsurf$tools,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_pkgsurf$tools);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_pkgsurf$tools);
        Py_DECREF(_spec_from_module);

        // We can assume this to never fail, or else we are in trouble anyway.
        // CHECK_OBJECT(spec_value);

        if (spec_value == NULL) {
            PyErr_PrintEx(0);
            abort();
        }

        // Mark the execution in the "__spec__" value.
        SET_ATTRIBUTE(tstate, spec_value, const_str_plain__initializing, Py_True);

#if _NUITKA_MODULE_MODE && 0 && 0 >= 0
        // Set our loader object in the "__spec__" value.
        SET_ATTRIBUTE(tstate, spec_value, const_str_plain_loader, module_loader);
#endif

        UPDATE_STRING_DICT1(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_pkgsurf$tools;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_pkgsurf$tools = MAKE_MODULE_FRAME(code_objects_b7977cb5d574123fdcec2f0464696b07, module_pkgsurf$tools);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_pkgsurf$tools);
assert(Py_REFCNT(frame_frame_pkgsurf$tools) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_pkgsurf$tools$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_pkgsurf$tools$__spec__(tstate);
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
        exception_tb = MAKE_TRACEBACK(frame_frame_pkgsurf$tools, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_pkgsurf$tools->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_pkgsurf$tools, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_pkgsurf$tools);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
{
PyObject *tmp_assign_source_3;
tmp_assign_source_3 = Py_None;
UPDATE_STRING_DICT0(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;

tmp_assign_source_5 = MAKE_FUNCTION_pkgsurf$tools$$$function__1_gather(tstate);

UPDATE_STRING_DICT1(moduledict_pkgsurf$tools, (Nuitka_StringObject *)mod_consts.const_str_plain_gather, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;

tmp_assign_source_6 = MAKE_FUNCTION_pkgsurf$tools$$$function__2_either(tstate);

UPDATE_STRING_DICT1(moduledict_pkgsurf$tools, (Nuitka_StringObject *)mod_consts.const_str_plain_either, tmp_assign_source_6);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("pkgsurf$tools", false);

#if _NUITKA_MODULE_MODE && 0
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "pkgsurf.tools" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_pkgsurf$tools);
    return module_pkgsurf$tools;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 0
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf$tools, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("pkgsurf$tools", false);

    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);
    return NULL;
}
