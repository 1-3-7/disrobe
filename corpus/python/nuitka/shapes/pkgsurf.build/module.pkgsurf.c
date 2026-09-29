/* Generated code for Python module 'pkgsurf'
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



/* The "module_pkgsurf" is a Python object pointer of module type.
 *
 * Note: For full compatibility with CPython, every module variable access
 * needs to go through it except for cases where the module cannot possibly
 * have changed in the mean time.
 */

PyObject *module_pkgsurf;
PyDictObject *moduledict_pkgsurf;

/* The declarations of module constants used, if any. */
static struct ModuleConstants {
PyObject *const_str_plain_environ;
PyObject *const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_str_plain_submodule_search_locations;
PyObject *const_str_plain_tools;
PyObject *const_tuple_str_plain_either_str_plain_gather_tuple;
PyObject *const_str_plain_either;
PyObject *const_str_plain_gather;
PyObject *const_str_digest_00d128b035dccba5857b9d6269921660;
PyObject *const_str_plain_version;
PyObject *const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2;
PyObject *const_str_digest_01514ef342ec42c5f85eee2fcf7054c5;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[13];
#endif

static PyObject *module_filename_obj = NULL;

/* Indicator if this modules private constants were created yet. */
static bool constants_created = false;

/* Function to create module private constants. */
static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("pkgsurf"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 13) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 13 values, got %d\n",
                    UN_TRANSLATE("pkgsurf"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_environ", mod_consts.const_str_plain_environ);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_str_plain_environ);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple", mod_consts.const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_submodule_search_locations", mod_consts.const_str_plain_submodule_search_locations);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_str_plain_submodule_search_locations);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_tools", mod_consts.const_str_plain_tools);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_str_plain_tools);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_either_str_plain_gather_tuple", mod_consts.const_tuple_str_plain_either_str_plain_gather_tuple);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_either_str_plain_gather_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_either", mod_consts.const_str_plain_either);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_str_plain_either);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_gather", mod_consts.const_str_plain_gather);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_str_plain_gather);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_00d128b035dccba5857b9d6269921660", mod_consts.const_str_digest_00d128b035dccba5857b9d6269921660);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_str_digest_00d128b035dccba5857b9d6269921660);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_version", mod_consts.const_str_plain_version);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_str_plain_version);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2", mod_consts.const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5", mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5);
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
void checkModuleConstants_pkgsurf(PyThreadState *tstate) {
    // The module may not have been used at all, then ignore this.
    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_environ", mod_consts.const_str_plain_environ);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_str_plain_environ) && "mod_consts.const_str_plain_environ");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple", mod_consts.const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple) && "mod_consts.const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_submodule_search_locations", mod_consts.const_str_plain_submodule_search_locations);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_str_plain_submodule_search_locations) && "mod_consts.const_str_plain_submodule_search_locations");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_tools", mod_consts.const_str_plain_tools);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_str_plain_tools) && "mod_consts.const_str_plain_tools");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_either_str_plain_gather_tuple", mod_consts.const_tuple_str_plain_either_str_plain_gather_tuple);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_either_str_plain_gather_tuple) && "mod_consts.const_tuple_str_plain_either_str_plain_gather_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_either", mod_consts.const_str_plain_either);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_str_plain_either) && "mod_consts.const_str_plain_either");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_gather", mod_consts.const_str_plain_gather);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_str_plain_gather) && "mod_consts.const_str_plain_gather");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_00d128b035dccba5857b9d6269921660", mod_consts.const_str_digest_00d128b035dccba5857b9d6269921660);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_str_digest_00d128b035dccba5857b9d6269921660) && "mod_consts.const_str_digest_00d128b035dccba5857b9d6269921660");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_version", mod_consts.const_str_plain_version);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_str_plain_version) && "mod_consts.const_str_plain_version");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2", mod_consts.const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2) && "mod_consts.const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5", mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5) && "mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5");
}
#endif

// Helper to preserving module variables for Python3.11+
#if 2
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
static PyObject *module_var_accessor_pkgsurf$__path__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_pkgsurf->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_pkgsurf->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___path__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_pkgsurf->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(const_str_plain___path__);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, const_str_plain___path__, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(const_str_plain___path__);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, const_str_plain___path__, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___path__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___path__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___path__);
    }

    return result;
}

static PyObject *module_var_accessor_pkgsurf$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_pkgsurf->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_pkgsurf->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_pkgsurf->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
// The module code objects.
static PyCodeObject *code_objects_49f6f97827b896e1f132ed8a558b7154;
static PyCodeObject *code_objects_5125d5c8e64f8d872e6bd42decd8130a;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_299ff24cbe2cf1133ba39c10fd1f85d2); CHECK_OBJECT(module_filename_obj);
code_objects_49f6f97827b896e1f132ed8a558b7154 = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5, mod_consts.const_str_digest_01514ef342ec42c5f85eee2fcf7054c5, NULL, NULL, 0, 0, 0);
code_objects_5125d5c8e64f8d872e6bd42decd8130a = MAKE_CODE_OBJECT(module_filename_obj, 4, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_version, mod_consts.const_str_plain_version, NULL, NULL, 0, 0, 0);
}
#endif

// The module function declarations.
static PyObject *MAKE_FUNCTION_pkgsurf$$$function__1_version(PyThreadState *tstate);


// The module function definitions.

static PyObject *MAKE_FUNCTION_pkgsurf$$$function__1_version(PyThreadState *tstate) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        NULL,
        mod_consts.const_str_plain_version,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_5125d5c8e64f8d872e6bd42decd8130a,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        NULL,
#endif
        module_pkgsurf,
        NULL,
        NULL,
        0
    );
Nuitka_Function_EnableConstReturnGeneric(result, mod_consts.const_str_digest_00d128b035dccba5857b9d6269921660);

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

static function_impl_code const function_table_pkgsurf[] = {

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

    return Nuitka_Function_GetFunctionState(function, function_table_pkgsurf);
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
        module_pkgsurf,
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
        function_table_pkgsurf,
        sizeof(function_table_pkgsurf) / sizeof(function_impl_code)
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
static char const *module_full_name = "pkgsurf";
#endif

// Internal entry point for module code.
PyObject *module_code_pkgsurf(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {
    // Report entry to PGO.
    PGO_onModuleEntered("pkgsurf");

    // Store the module for future use.
    module_pkgsurf = module;

    moduledict_pkgsurf = MODULE_DICT(module_pkgsurf);

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
        PRINT_STRING("pkgsurf: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("pkgsurf: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("pkgsurf: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "pkgsurf" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in initpkgsurf\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___name__);
            module_name_c = Nuitka_String_AsString(module_name);
        }

        registerDillPluginTables(tstate, module_name_c, &_method_def_reduce_compiled_function, &_method_def_create_compiled_function);
    }
#endif

    // For Python 3.11 standalone modules, package "__path__" is inserted by the
    // loader before module code runs. Pre-seed "__compiled__" for non-packages
    // to keep their dangerous dict slots aligned with packages.
#if PYTHON_VERSION >= 0x3b0 && PYTHON_VERSION < 0x3c0 && _NUITKA_STANDALONE_MODE && !1
    UPDATE_STRING_DICT0(
        moduledict_pkgsurf,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_pkgsurf,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 1
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_pkgsurf,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_pkgsurf,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_pkgsurf,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_pkgsurf);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_pkgsurf);
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

        UPDATE_STRING_DICT1(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
PyObject *tmp_import_from_1__module = NULL;
struct Nuitka_FrameObject *frame_frame_pkgsurf;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_1;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_1;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_pkgsurf = MAKE_MODULE_FRAME(code_objects_49f6f97827b896e1f132ed8a558b7154, module_pkgsurf);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_pkgsurf);
assert(Py_REFCNT(frame_frame_pkgsurf) == 2);

// Framed code:
{
PyObject *tmp_assign_source_3;
PyObject *tmp_list_element_1;
PyObject *tmp_called_value_1;
PyObject *tmp_expression_value_1;
PyObject *tmp_args_element_value_1;
frame_frame_pkgsurf->m_frame.f_lineno = 1;
{
    PyObject *hard_module = IMPORT_HARD_OS();
    if (likely(hard_module != NULL)) {
        tmp_expression_value_1 = LOOKUP_ATTRIBUTE(tstate, hard_module, const_str_plain_path);


    } else {
        tmp_expression_value_1 = NULL;
    }
}
if (tmp_expression_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto frame_exception_exit_1;
}
tmp_called_value_1 = LOOKUP_ATTRIBUTE(tstate, tmp_expression_value_1, const_str_plain_dirname);
CHECK_OBJECT(tmp_expression_value_1);
Py_DECREF(tmp_expression_value_1);
if (tmp_called_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto frame_exception_exit_1;
}
tmp_args_element_value_1 = module_filename_obj;
frame_frame_pkgsurf->m_frame.f_lineno = 1;
tmp_list_element_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_1, tmp_args_element_value_1);
CHECK_OBJECT(tmp_called_value_1);
Py_DECREF(tmp_called_value_1);
if (tmp_list_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto frame_exception_exit_1;
}
tmp_assign_source_3 = MAKE_LIST_EMPTY(tstate, 2);
{
PyObject *tmp_called_value_2;
PyObject *tmp_expression_value_2;
PyList_SET_ITEM(tmp_assign_source_3, 0, tmp_list_element_1);
frame_frame_pkgsurf->m_frame.f_lineno = 1;
{
    PyObject *hard_module = IMPORT_HARD_OS();
    if (likely(hard_module != NULL)) {
        tmp_expression_value_2 = LOOKUP_ATTRIBUTE(tstate, hard_module, mod_consts.const_str_plain_environ);


    } else {
        tmp_expression_value_2 = NULL;
    }
}
if (tmp_expression_value_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto list_build_exception_1;
}
tmp_called_value_2 = LOOKUP_ATTRIBUTE(tstate, tmp_expression_value_2, const_str_plain_get);
CHECK_OBJECT(tmp_expression_value_2);
Py_DECREF(tmp_expression_value_2);
if (tmp_called_value_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto list_build_exception_1;
}
frame_frame_pkgsurf->m_frame.f_lineno = 1;
tmp_list_element_1 = CALL_FUNCTION_WITH_POS_ARGS2(tstate, tmp_called_value_2, mod_consts.const_tuple_cb76cd7d1b5eaea7df4f496f27a4d137_tuple);

CHECK_OBJECT(tmp_called_value_2);
Py_DECREF(tmp_called_value_2);
if (tmp_list_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto list_build_exception_1;
}
PyList_SET_ITEM(tmp_assign_source_3, 1, tmp_list_element_1);
}
goto list_build_no_exception_1;
// Exception handling pass through code for list_build:
list_build_exception_1:;
Py_DECREF(tmp_assign_source_3);
goto frame_exception_exit_1;
// Finished with no exception for list_build:
list_build_no_exception_1:;
UPDATE_STRING_DICT1(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___path__, tmp_assign_source_3);
}
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_pkgsurf$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_pkgsurf$__spec__(tstate);
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
PyObject *tmp_ass_attr_value_3;
PyObject *tmp_ass_attr_target_3;
tmp_ass_attr_value_3 = module_var_accessor_pkgsurf$__path__(tstate);
if (unlikely(tmp_ass_attr_value_3 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, const_str_plain___path__);
}

if (tmp_ass_attr_value_3 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));



exception_lineno = 1;

    goto frame_exception_exit_1;
}
tmp_ass_attr_target_3 = module_var_accessor_pkgsurf$__spec__(tstate);
assert(!(tmp_ass_attr_target_3 == NULL));
tmp_result = SET_ATTRIBUTE(tstate, tmp_ass_attr_target_3, mod_consts.const_str_plain_submodule_search_locations, tmp_ass_attr_value_3);
if (tmp_result == false) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto frame_exception_exit_1;
}
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Py_None;
UPDATE_STRING_DICT0(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
tmp_assign_source_5 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
PyObject *tmp_name_value_1;
PyObject *tmp_globals_arg_value_1;
PyObject *tmp_locals_arg_value_1;
PyObject *tmp_fromlist_value_1;
PyObject *tmp_level_value_1;
tmp_name_value_1 = mod_consts.const_str_plain_tools;
tmp_globals_arg_value_1 = (PyObject *)moduledict_pkgsurf;
tmp_locals_arg_value_1 = Py_None;
tmp_fromlist_value_1 = mod_consts.const_tuple_str_plain_either_str_plain_gather_tuple;
tmp_level_value_1 = const_int_pos_1;
frame_frame_pkgsurf->m_frame.f_lineno = 1;
tmp_assign_source_6 = IMPORT_MODULE5(tstate, tmp_name_value_1, tmp_globals_arg_value_1, tmp_locals_arg_value_1, tmp_fromlist_value_1, tmp_level_value_1);
if (tmp_assign_source_6 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto frame_exception_exit_1;
}
assert(tmp_import_from_1__module == NULL);
tmp_import_from_1__module = tmp_assign_source_6;
}
// Tried code:
{
PyObject *tmp_assign_source_7;
PyObject *tmp_import_name_from_1;
CHECK_OBJECT(tmp_import_from_1__module);
tmp_import_name_from_1 = tmp_import_from_1__module;
if (PyModule_Check(tmp_import_name_from_1)) {
    tmp_assign_source_7 = IMPORT_NAME_OR_MODULE(
        tstate,
        tmp_import_name_from_1,
        (PyObject *)moduledict_pkgsurf,
        mod_consts.const_str_plain_either,
        const_int_0
    );
} else {
    tmp_assign_source_7 = IMPORT_NAME_FROM_MODULE(tstate, tmp_import_name_from_1, mod_consts.const_str_plain_either);
}

if (tmp_assign_source_7 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto try_except_handler_1;
}
UPDATE_STRING_DICT1(moduledict_pkgsurf, (Nuitka_StringObject *)mod_consts.const_str_plain_either, tmp_assign_source_7);
}
{
PyObject *tmp_assign_source_8;
PyObject *tmp_import_name_from_2;
CHECK_OBJECT(tmp_import_from_1__module);
tmp_import_name_from_2 = tmp_import_from_1__module;
if (PyModule_Check(tmp_import_name_from_2)) {
    tmp_assign_source_8 = IMPORT_NAME_OR_MODULE(
        tstate,
        tmp_import_name_from_2,
        (PyObject *)moduledict_pkgsurf,
        mod_consts.const_str_plain_gather,
        const_int_0
    );
} else {
    tmp_assign_source_8 = IMPORT_NAME_FROM_MODULE(tstate, tmp_import_name_from_2, mod_consts.const_str_plain_gather);
}

if (tmp_assign_source_8 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 1;

    goto try_except_handler_1;
}
UPDATE_STRING_DICT1(moduledict_pkgsurf, (Nuitka_StringObject *)mod_consts.const_str_plain_gather, tmp_assign_source_8);
}
goto try_end_1;
// Exception handler code:
try_except_handler_1:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(tmp_import_from_1__module);
CHECK_OBJECT(tmp_import_from_1__module);
Py_DECREF(tmp_import_from_1__module);
tmp_import_from_1__module = NULL;
// Re-raise.
exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto frame_exception_exit_1;
// End of try:
try_end_1:;


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_pkgsurf, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_pkgsurf->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_pkgsurf, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}



assertFrameObject(frame_frame_pkgsurf);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;
CHECK_OBJECT(tmp_import_from_1__module);
CHECK_OBJECT(tmp_import_from_1__module);
Py_DECREF(tmp_import_from_1__module);
tmp_import_from_1__module = NULL;
{
PyObject *tmp_assign_source_9;

tmp_assign_source_9 = MAKE_FUNCTION_pkgsurf$$$function__1_version(tstate);

UPDATE_STRING_DICT1(moduledict_pkgsurf, (Nuitka_StringObject *)mod_consts.const_str_plain_version, tmp_assign_source_9);
}

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("pkgsurf", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "pkgsurf" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_pkgsurf);
    return module_pkgsurf;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_pkgsurf, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("pkgsurf", false);

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
            moduledict_pkgsurf,
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
static struct PyModuleDef mdef_pkgsurf = {
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
            moduledict_pkgsurf,
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

static PyObject *PyInit_pkgsurf_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_pkgsurf(tstate, module, getLoaderEntry("pkgsurf"));

#if PYTHON_VERSION < 0x300
    // Our "__file__" value will not be respected by CPython and one
    // way we can avoid it, is by having a capsule type, that when
    // it gets released, we are called and repair the value.

    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_pkgsurf, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_pkgsurf,
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

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_pkgsurf, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_pkgsurf_slot(PyObject *module) {
    PyObject *result = PyInit_pkgsurf_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_pkgsurf)(void) {
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
    mdef_pkgsurf.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_pkgsurf);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_pkgsurf_slot},
        {0, NULL}
    };

    mdef_pkgsurf.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_pkgsurf);
#elif PYTHON_VERSION >= 0x300
    return PyInit_pkgsurf_phase2(module);
#else
    PyInit_pkgsurf_phase2(module);
#endif
}
