

#include "nuitka/prelude.h"

#include "nuitka/unfreezing.h"

#include "__helpers.h"


PyObject *module_hello;
PyDictObject *moduledict_hello;


static struct ModuleConstants {
PyObject *const_str_digest_9ee70a5c303845daec9e23bee0b001a7;
PyObject *const_int_pos_2;
PyObject *const_tuple_int_0_int_pos_1_tuple;
PyObject *const_str_plain_a;
PyObject *const_str_plain_greet;
PyObject *const_tuple_str_plain_disrobe_tuple;
PyObject *const_str_plain_fib;
PyObject *const_tuple_int_pos_20_tuple;
PyObject *const_str_plain_origin;
PyObject *const_str_plain_has_location;
PyObject *const_dict_0d747635c5b87742d1bd242db31edac3;
PyObject *const_dict_ac2d17ccf098d71f8de0232b23b5a904;
PyObject *const_dict_1259841a0de68bdf7d5f55bbd030b617;
PyObject *const_str_plain_main;
PyObject *const_str_plain___main__;
PyObject *const_str_digest_acb2cd27d0b8865026bf56b8641e0136;
PyObject *const_str_digest_d2afd2076c694b14cee62c32caa68d1d;
PyObject *const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple;
PyObject *const_tuple_str_plain_name_tuple;
} mod_consts;
#ifndef __NUITKA_NO_ASSERT__
static Py_hash_t mod_consts_hash[19];
#endif

static PyObject *module_filename_obj = NULL;


static bool constants_created = false;


static void createModuleConstants(PyThreadState *tstate) {
    if (constants_created == false) {
        NUITKA_MAY_BE_UNUSED int constants_loaded_count =
            loadConstantsBlob(tstate, (PyObject **)&mod_consts, UN_TRANSLATE("hello"));
        constants_created = true;

#ifndef __NUITKA_NO_ASSERT__
        if (constants_loaded_count != 19) {
            fprintf(stderr,
                    "Corrupt constants blob for %s: expected 19 values, got %d\n",
                    UN_TRANSLATE("hello"),
                    constants_loaded_count);
            fflush(stderr);
            abort();
        }

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7", mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7);
mod_consts_hash[0] = DEEP_HASH(tstate, mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_2", mod_consts.const_int_pos_2);
mod_consts_hash[1] = DEEP_HASH(tstate, mod_consts.const_int_pos_2);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_0_int_pos_1_tuple", mod_consts.const_tuple_int_0_int_pos_1_tuple);
mod_consts_hash[2] = DEEP_HASH(tstate, mod_consts.const_tuple_int_0_int_pos_1_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_a", mod_consts.const_str_plain_a);
mod_consts_hash[3] = DEEP_HASH(tstate, mod_consts.const_str_plain_a);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_greet", mod_consts.const_str_plain_greet);
mod_consts_hash[4] = DEEP_HASH(tstate, mod_consts.const_str_plain_greet);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_disrobe_tuple", mod_consts.const_tuple_str_plain_disrobe_tuple);
mod_consts_hash[5] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_disrobe_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_fib", mod_consts.const_str_plain_fib);
mod_consts_hash[6] = DEEP_HASH(tstate, mod_consts.const_str_plain_fib);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_20_tuple", mod_consts.const_tuple_int_pos_20_tuple);
mod_consts_hash[7] = DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_20_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
mod_consts_hash[8] = DEEP_HASH(tstate, mod_consts.const_str_plain_origin);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
mod_consts_hash[9] = DEEP_HASH(tstate, mod_consts.const_str_plain_has_location);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3", mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3);
mod_consts_hash[10] = DEEP_HASH(tstate, mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
mod_consts_hash[11] = DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617", mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617);
mod_consts_hash[12] = DEEP_HASH(tstate, mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_main", mod_consts.const_str_plain_main);
mod_consts_hash[13] = DEEP_HASH(tstate, mod_consts.const_str_plain_main);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain___main__", mod_consts.const_str_plain___main__);
mod_consts_hash[14] = DEEP_HASH(tstate, mod_consts.const_str_plain___main__);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_acb2cd27d0b8865026bf56b8641e0136", mod_consts.const_str_digest_acb2cd27d0b8865026bf56b8641e0136);
mod_consts_hash[15] = DEEP_HASH(tstate, mod_consts.const_str_digest_acb2cd27d0b8865026bf56b8641e0136);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d", mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d);
mod_consts_hash[16] = DEEP_HASH(tstate, mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple", mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
mod_consts_hash[17] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_name_tuple", mod_consts.const_tuple_str_plain_name_tuple);
mod_consts_hash[18] = DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_name_tuple);
#endif
    }
}


#if 0
void createMainModuleConstants(PyThreadState *tstate) {
    createModuleConstants(tstate);
}
#endif


#ifndef __NUITKA_NO_ASSERT__
void checkModuleConstants_hello(PyThreadState *tstate) {

    if (constants_created == false) return;

CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7", mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7);
assert(mod_consts_hash[0] == DEEP_HASH(tstate, mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7) && "mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_int_pos_2", mod_consts.const_int_pos_2);
assert(mod_consts_hash[1] == DEEP_HASH(tstate, mod_consts.const_int_pos_2) && "mod_consts.const_int_pos_2");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_0_int_pos_1_tuple", mod_consts.const_tuple_int_0_int_pos_1_tuple);
assert(mod_consts_hash[2] == DEEP_HASH(tstate, mod_consts.const_tuple_int_0_int_pos_1_tuple) && "mod_consts.const_tuple_int_0_int_pos_1_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_a", mod_consts.const_str_plain_a);
assert(mod_consts_hash[3] == DEEP_HASH(tstate, mod_consts.const_str_plain_a) && "mod_consts.const_str_plain_a");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_greet", mod_consts.const_str_plain_greet);
assert(mod_consts_hash[4] == DEEP_HASH(tstate, mod_consts.const_str_plain_greet) && "mod_consts.const_str_plain_greet");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_disrobe_tuple", mod_consts.const_tuple_str_plain_disrobe_tuple);
assert(mod_consts_hash[5] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_disrobe_tuple) && "mod_consts.const_tuple_str_plain_disrobe_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_fib", mod_consts.const_str_plain_fib);
assert(mod_consts_hash[6] == DEEP_HASH(tstate, mod_consts.const_str_plain_fib) && "mod_consts.const_str_plain_fib");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_int_pos_20_tuple", mod_consts.const_tuple_int_pos_20_tuple);
assert(mod_consts_hash[7] == DEEP_HASH(tstate, mod_consts.const_tuple_int_pos_20_tuple) && "mod_consts.const_tuple_int_pos_20_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_origin", mod_consts.const_str_plain_origin);
assert(mod_consts_hash[8] == DEEP_HASH(tstate, mod_consts.const_str_plain_origin) && "mod_consts.const_str_plain_origin");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_has_location", mod_consts.const_str_plain_has_location);
assert(mod_consts_hash[9] == DEEP_HASH(tstate, mod_consts.const_str_plain_has_location) && "mod_consts.const_str_plain_has_location");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3", mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3);
assert(mod_consts_hash[10] == DEEP_HASH(tstate, mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3) && "mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904", mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);
assert(mod_consts_hash[11] == DEEP_HASH(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904) && "mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617", mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617);
assert(mod_consts_hash[12] == DEEP_HASH(tstate, mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617) && "mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain_main", mod_consts.const_str_plain_main);
assert(mod_consts_hash[13] == DEEP_HASH(tstate, mod_consts.const_str_plain_main) && "mod_consts.const_str_plain_main");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_plain___main__", mod_consts.const_str_plain___main__);
assert(mod_consts_hash[14] == DEEP_HASH(tstate, mod_consts.const_str_plain___main__) && "mod_consts.const_str_plain___main__");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_acb2cd27d0b8865026bf56b8641e0136", mod_consts.const_str_digest_acb2cd27d0b8865026bf56b8641e0136);
assert(mod_consts_hash[15] == DEEP_HASH(tstate, mod_consts.const_str_digest_acb2cd27d0b8865026bf56b8641e0136) && "mod_consts.const_str_digest_acb2cd27d0b8865026bf56b8641e0136");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d", mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d);
assert(mod_consts_hash[16] == DEEP_HASH(tstate, mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d) && "mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple", mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple);
assert(mod_consts_hash[17] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple) && "mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple");
CHECK_OBJECT_DEEP_NAMED("mod_consts.const_tuple_str_plain_name_tuple", mod_consts.const_tuple_str_plain_name_tuple);
assert(mod_consts_hash[18] == DEEP_HASH(tstate, mod_consts.const_tuple_str_plain_name_tuple) && "mod_consts.const_tuple_str_plain_name_tuple");
}
#endif


#if 5
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


static PyObject *module_var_accessor_hello$__name__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_hello->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_hello->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___name__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_hello->ma_keys;
    if (likely(DK_IS_UNICODE(dk))) {

#if PYTHON_VERSION >= 0x3c0
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(tstate->interp, dk);
#else
        uint32_t current_dk_version = _Nuitka_PyDictKeys_GetVersionForCurrentState(dk);
#endif

        if (current_dk_version != dict_keys_version) {
            dict_keys_version = current_dk_version;
            Py_hash_t hash = Nuitka_Py_unicode_get_hash(const_str_plain___name__);
            assert(hash != -1);

            cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, const_str_plain___name__, hash);
        }

        if (cache_dk_index >= 0) {
            assert(dk->dk_kind != DICT_KEYS_SPLIT);

            PyDictUnicodeEntry *entries = DK_UNICODE_ENTRIES(dk);

            result = entries[cache_dk_index].me_value;

            if (unlikely(result == NULL)) {
                Py_hash_t hash = Nuitka_Py_unicode_get_hash(const_str_plain___name__);
                assert(hash != -1);

                cache_dk_index = Nuitka_Py_unicodekeys_lookup_unicode(dk, const_str_plain___name__, hash);

                if (cache_dk_index >= 0) {
                    result = entries[cache_dk_index].me_value;
                }
            }
        } else {
            result = NULL;
        }
    } else {
        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___name__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___name__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___name__);
    }

    return result;
}

static PyObject *module_var_accessor_hello$__spec__(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_hello->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_hello->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___spec__);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_hello->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___spec__);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___spec__);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)const_str_plain___spec__);
    }

    return result;
}

static PyObject *module_var_accessor_hello$fib(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_hello->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_hello->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_hello->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_fib);
    }

    return result;
}

static PyObject *module_var_accessor_hello$greet(PyThreadState *tstate) {
#if 1
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_hello->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_hello->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_hello->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_greet);
    }

    return result;
}

static PyObject *module_var_accessor_hello$main(PyThreadState *tstate) {
#if 0
    PyObject *result;

#if PYTHON_VERSION < 0x3b0
    static uint64_t dict_version = 0;
    static PyObject *cache_value = NULL;

    if (moduledict_hello->ma_version_tag == dict_version) {
        CHECK_OBJECT_X(cache_value);
        result = cache_value;
    } else {
        dict_version = moduledict_hello->ma_version_tag;

        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_main);
        cache_value = result;
    }
#else
    static uint32_t dict_keys_version = 0xFFFFFFFF;
    static Py_ssize_t cache_dk_index = 0;

    PyDictKeysObject *dk = moduledict_hello->ma_keys;
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
        result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_main);
    }
#endif

#else
    PyObject *result = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_main);
#endif

    if (unlikely(result == NULL)) {
        result = GET_STRING_DICT_VALUE(dict_builtin, (Nuitka_StringObject *)mod_consts.const_str_plain_main);
    }

    return result;
}


#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)

static PyCodeObject *code_objects_63ff75d9da1f95ed670f72b94af33f37;
static PyCodeObject *code_objects_e6de52e36e476551b386f8b9a74be9a3;
static PyCodeObject *code_objects_4efcdcb3057fb04504680af5b1b5501d;
static PyCodeObject *code_objects_a8ac380f9efefefb6c4e470afd77f585;

static void createModuleCodeObjects(void) {
module_filename_obj = MAKE_RELATIVE_PATH(mod_consts.const_str_digest_acb2cd27d0b8865026bf56b8641e0136); CHECK_OBJECT(module_filename_obj);
code_objects_63ff75d9da1f95ed670f72b94af33f37 = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d, mod_consts.const_str_digest_d2afd2076c694b14cee62c32caa68d1d, NULL, NULL, 0, 0, 0);
code_objects_e6de52e36e476551b386f8b9a74be9a3 = MAKE_CODE_OBJECT(module_filename_obj, 4, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_fib, mod_consts.const_str_plain_fib, mod_consts.const_tuple_str_plain_n_str_plain_a_str_plain_b_str_underscore_tuple, NULL, 1, 0, 0);
code_objects_4efcdcb3057fb04504680af5b1b5501d = MAKE_CODE_OBJECT(module_filename_obj, 1, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_greet, mod_consts.const_str_plain_greet, mod_consts.const_tuple_str_plain_name_tuple, NULL, 1, 0, 0);
code_objects_a8ac380f9efefefb6c4e470afd77f585 = MAKE_CODE_OBJECT(module_filename_obj, 12, CO_OPTIMIZED | CO_NEWLOCALS, mod_consts.const_str_plain_main, mod_consts.const_str_plain_main, NULL, NULL, 0, 0, 0);
}
#endif


static PyObject *MAKE_FUNCTION_hello$$$function__1_greet(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_hello$$$function__2_fib(PyThreadState *tstate, PyObject *annotations);


static PyObject *MAKE_FUNCTION_hello$$$function__3_main(PyThreadState *tstate, PyObject *annotations);


static PyObject *impl_hello$$$function__1_greet(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {

#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif


PyObject *par_name = python_pars[0];
struct Nuitka_FrameObject *frame_frame_hello$$$function__1_greet;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
PyObject *tmp_return_value = NULL;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_hello$$$function__1_greet = NULL;


if (isFrameUnusable(cache_frame_frame_hello$$$function__1_greet)) {
    Py_XDECREF(cache_frame_frame_hello$$$function__1_greet);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_hello$$$function__1_greet == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_hello$$$function__1_greet = MAKE_FUNCTION_FRAME(tstate, code_objects_4efcdcb3057fb04504680af5b1b5501d, module_hello, sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_hello$$$function__1_greet->m_type_description == NULL);
frame_frame_hello$$$function__1_greet = cache_frame_frame_hello$$$function__1_greet;


pushFrameStackCompiledFrame(tstate, frame_frame_hello$$$function__1_greet);
assert(Py_REFCNT(frame_frame_hello$$$function__1_greet) == 2);


{
PyObject *tmp_string_concat_values_1;
PyObject *tmp_tuple_element_1;
tmp_tuple_element_1 = mod_consts.const_str_digest_9ee70a5c303845daec9e23bee0b001a7;
tmp_string_concat_values_1 = MAKE_TUPLE_EMPTY(tstate, 2);
{
PyObject *tmp_format_value_1;
PyObject *tmp_format_spec_1;
PyTuple_SET_ITEM0(tmp_string_concat_values_1, 0, tmp_tuple_element_1);
CHECK_OBJECT(par_name);
tmp_format_value_1 = par_name;
tmp_format_spec_1 = const_str_empty;
tmp_tuple_element_1 = BUILTIN_FORMAT(tstate, tmp_format_value_1, tmp_format_spec_1);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 2;
type_description_1 = "o";
    goto tuple_build_exception_1;
}
PyTuple_SET_ITEM(tmp_string_concat_values_1, 1, tmp_tuple_element_1);
}
goto tuple_build_no_exception_1;

tuple_build_exception_1:;
Py_DECREF(tmp_string_concat_values_1);
goto frame_exception_exit_1;

tuple_build_no_exception_1:;
tmp_return_value = PyUnicode_Join(const_str_empty, tmp_string_concat_values_1);
CHECK_OBJECT(tmp_string_concat_values_1);
Py_DECREF(tmp_string_concat_values_1);
assert(!(tmp_return_value == NULL));
goto frame_return_exit_1;
}


popFrameStack(tstate);

goto frame_no_exception_1;
frame_return_exit_1:


popFrameStack(tstate);

goto function_return_exit;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_hello$$$function__1_greet, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_hello$$$function__1_greet->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_hello$$$function__1_greet, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}


Nuitka_Frame_AttachLocals(
    frame_frame_hello$$$function__1_greet,
    type_description_1,
    par_name
);


if (frame_frame_hello$$$function__1_greet == cache_frame_frame_hello$$$function__1_greet) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_hello$$$function__1_greet);
    cache_frame_frame_hello$$$function__1_greet = NULL;
}

assertFrameObject(frame_frame_hello$$$function__1_greet);


popFrameStack(tstate);


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

CHECK_OBJECT(par_name);
Py_DECREF(par_name);


   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_hello$$$function__2_fib(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {

#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif


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
struct Nuitka_FrameObject *frame_frame_hello$$$function__2_fib;
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
static struct Nuitka_FrameObject *cache_frame_frame_hello$$$function__2_fib = NULL;
struct Nuitka_ExceptionPreservationItem exception_keeper_name_6;
NUITKA_MAY_BE_UNUSED int exception_keeper_lineno_6;


if (isFrameUnusable(cache_frame_frame_hello$$$function__2_fib)) {
    Py_XDECREF(cache_frame_frame_hello$$$function__2_fib);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_hello$$$function__2_fib == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_hello$$$function__2_fib = MAKE_FUNCTION_FRAME(tstate, code_objects_e6de52e36e476551b386f8b9a74be9a3, module_hello, sizeof(void *)+sizeof(void *)+sizeof(void *)+sizeof(void *));
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_hello$$$function__2_fib->m_type_description == NULL);
frame_frame_hello$$$function__2_fib = cache_frame_frame_hello$$$function__2_fib;


pushFrameStackCompiledFrame(tstate, frame_frame_hello$$$function__2_fib);
assert(Py_REFCNT(frame_frame_hello$$$function__2_fib) == 2);


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


exception_lineno = 5;
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


{
PyObject *tmp_assign_source_2;
PyObject *tmp_unpack_1;
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
tmp_unpack_1 = tmp_tuple_unpack_1__source_iter;
tmp_assign_source_2 = UNPACK_NEXT(tstate, &exception_state, tmp_unpack_1, 0, 2);
if (tmp_assign_source_2 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));


exception_lineno = 7;
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


exception_lineno = 7;
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


exception_lineno = 7;
type_description_1 = "oooo";
    goto try_except_handler_3;
}
}
goto try_end_1;

try_except_handler_3:;
exception_keeper_lineno_1 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_1 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
CHECK_OBJECT(tmp_tuple_unpack_1__source_iter);
Py_DECREF(tmp_tuple_unpack_1__source_iter);
tmp_tuple_unpack_1__source_iter = NULL;

exception_state = exception_keeper_name_1;
exception_lineno = exception_keeper_lineno_1;

goto try_except_handler_2;

try_end_1:;
goto try_end_2;

try_except_handler_2:;
exception_keeper_lineno_2 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_2 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_tuple_unpack_1__element_1);
tmp_tuple_unpack_1__element_1 = NULL;
Py_XDECREF(tmp_tuple_unpack_1__element_2);
tmp_tuple_unpack_1__element_2 = NULL;

exception_state = exception_keeper_name_2;
exception_lineno = exception_keeper_lineno_2;

goto frame_exception_exit_1;

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


exception_lineno = 8;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
tmp_iter_arg_2 = BUILTIN_XRANGE1(tstate, tmp_xrange_low_1);
CHECK_OBJECT(tmp_xrange_low_1);
Py_DECREF(tmp_xrange_low_1);
if (tmp_iter_arg_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 8;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
tmp_assign_source_6 = MAKE_ITERATOR(tstate, tmp_iter_arg_2);
CHECK_OBJECT(tmp_iter_arg_2);
Py_DECREF(tmp_iter_arg_2);
if (tmp_assign_source_6 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 8;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}
{
    PyObject *old = tmp_for_loop_1__for_iterator;
    tmp_for_loop_1__for_iterator = tmp_assign_source_6;
    Py_XDECREF(old);
}

}

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
exception_lineno = 8;
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

{
PyObject *tmp_assign_source_9;
PyObject *tmp_iter_arg_3;
PyObject *tmp_tuple_element_1;
if (var_b == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, const_str_plain_b);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 9;
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

exception_lineno = 9;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}

tmp_add_expr_left_1 = var_a;
if (var_b == NULL) {

FORMAT_UNBOUND_LOCAL_ERROR(tstate, &exception_state, const_str_plain_b);
CHAIN_EXCEPTION(tstate, exception_state.exception_value);

exception_lineno = 9;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}

tmp_add_expr_right_1 = var_b;
tmp_tuple_element_1 = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
if (tmp_tuple_element_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 9;
type_description_1 = "oooo";
    goto tuple_build_exception_1;
}
PyTuple_SET_ITEM(tmp_iter_arg_3, 1, tmp_tuple_element_1);
}
goto tuple_build_no_exception_1;

tuple_build_exception_1:;
Py_DECREF(tmp_iter_arg_3);
goto try_except_handler_5;

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

{
PyObject *tmp_assign_source_10;
PyObject *tmp_unpack_3;
CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
tmp_unpack_3 = tmp_tuple_unpack_2__source_iter;
tmp_assign_source_10 = UNPACK_NEXT(tstate, &exception_state, tmp_unpack_3, 0, 2);
if (tmp_assign_source_10 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));


exception_lineno = 9;
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


exception_lineno = 9;
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


exception_lineno = 9;
type_description_1 = "oooo";
    goto try_except_handler_6;
}
}
goto try_end_3;

try_except_handler_6:;
exception_keeper_lineno_3 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_3 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
CHECK_OBJECT(tmp_tuple_unpack_2__source_iter);
Py_DECREF(tmp_tuple_unpack_2__source_iter);
tmp_tuple_unpack_2__source_iter = NULL;

exception_state = exception_keeper_name_3;
exception_lineno = exception_keeper_lineno_3;

goto try_except_handler_5;

try_end_3:;
goto try_end_4;

try_except_handler_5:;
exception_keeper_lineno_4 = exception_lineno;
exception_lineno = 0;
exception_keeper_name_4 = exception_state;
INIT_ERROR_OCCURRED_STATE(&exception_state);

Py_XDECREF(tmp_tuple_unpack_2__element_1);
tmp_tuple_unpack_2__element_1 = NULL;
Py_XDECREF(tmp_tuple_unpack_2__element_2);
tmp_tuple_unpack_2__element_2 = NULL;

exception_state = exception_keeper_name_4;
exception_lineno = exception_keeper_lineno_4;

goto try_except_handler_4;

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


exception_lineno = 8;
type_description_1 = "oooo";
    goto try_except_handler_4;
}
goto loop_start_1;
loop_end_1:;
goto try_end_5;

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

exception_state = exception_keeper_name_5;
exception_lineno = exception_keeper_lineno_5;

goto frame_exception_exit_1;

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

exception_lineno = 10;
type_description_1 = "oooo";
    goto frame_exception_exit_1;
}

tmp_return_value = var_b;
Py_INCREF(tmp_return_value);
goto frame_return_exit_1;


popFrameStack(tstate);

goto frame_no_exception_1;
frame_return_exit_1:


popFrameStack(tstate);

goto try_return_handler_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_hello$$$function__2_fib, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_hello$$$function__2_fib->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_hello$$$function__2_fib, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}


Nuitka_Frame_AttachLocals(
    frame_frame_hello$$$function__2_fib,
    type_description_1,
    par_n,
    var_a,
    var_b,
    var__
);


if (frame_frame_hello$$$function__2_fib == cache_frame_frame_hello$$$function__2_fib) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_hello$$$function__2_fib);
    cache_frame_frame_hello$$$function__2_fib = NULL;
}

assertFrameObject(frame_frame_hello$$$function__2_fib);


popFrameStack(tstate);


goto try_except_handler_1;
frame_no_exception_1:;
NUITKA_CANNOT_GET_HERE("tried codes exits in all cases");
return NULL;

try_return_handler_1:;
Py_XDECREF(var_a);
var_a = NULL;
Py_XDECREF(var_b);
var_b = NULL;
Py_XDECREF(var__);
var__ = NULL;
goto function_return_exit;

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

exception_state = exception_keeper_name_6;
exception_lineno = exception_keeper_lineno_6;

goto function_exception_exit;


NUITKA_CANNOT_GET_HERE("Return statement must have exited already.");
return NULL;

function_exception_exit:
CHECK_OBJECT(par_n);
Py_DECREF(par_n);
    CHECK_EXCEPTION_STATE(&exception_state);
    RESTORE_ERROR_OCCURRED_STATE(tstate, &exception_state);

    return NULL;

function_return_exit:

CHECK_OBJECT(par_n);
Py_DECREF(par_n);


   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *impl_hello$$$function__3_main(PyThreadState *tstate, struct Nuitka_FunctionObject const *self, PyObject **python_pars) {

#ifndef __NUITKA_NO_ASSERT__
    NUITKA_MAY_BE_UNUSED bool had_error = HAS_ERROR_OCCURRED(tstate);
#endif


struct Nuitka_FrameObject *frame_frame_hello$$$function__3_main;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
NUITKA_MAY_BE_UNUSED nuitka_void tmp_unused;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;
static struct Nuitka_FrameObject *cache_frame_frame_hello$$$function__3_main = NULL;
PyObject *tmp_return_value = NULL;


if (isFrameUnusable(cache_frame_frame_hello$$$function__3_main)) {
    Py_XDECREF(cache_frame_frame_hello$$$function__3_main);

#if _DEBUG_REFCOUNTS
    if (cache_frame_frame_hello$$$function__3_main == NULL) {
        count_active_frame_cache_instances += 1;
    } else {
        count_released_frame_cache_instances += 1;
    }
    count_allocated_frame_cache_instances += 1;
#endif
    cache_frame_frame_hello$$$function__3_main = MAKE_FUNCTION_FRAME(tstate, code_objects_a8ac380f9efefefb6c4e470afd77f585, module_hello, 0);
#if _DEBUG_REFCOUNTS
} else {
    count_hit_frame_cache_instances += 1;
#endif
}

assert(cache_frame_frame_hello$$$function__3_main->m_type_description == NULL);
frame_frame_hello$$$function__3_main = cache_frame_frame_hello$$$function__3_main;


pushFrameStackCompiledFrame(tstate, frame_frame_hello$$$function__3_main);
assert(Py_REFCNT(frame_frame_hello$$$function__3_main) == 2);


{
PyObject *tmp_called_value_1;
PyObject *tmp_call_result_1;
PyObject *tmp_args_element_value_1;
PyObject *tmp_called_value_2;
tmp_called_value_1 = LOOKUP_BUILTIN(const_str_plain_print);
assert(tmp_called_value_1 != NULL);
tmp_called_value_2 = module_var_accessor_hello$greet(tstate);
if (unlikely(tmp_called_value_2 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_greet);
}

if (tmp_called_value_2 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));


exception_lineno = 13;

    goto frame_exception_exit_1;
}
frame_frame_hello$$$function__3_main->m_frame.f_lineno = 13;
tmp_args_element_value_1 = CALL_FUNCTION_WITH_POS_ARGS1(tstate, tmp_called_value_2, mod_consts.const_tuple_str_plain_disrobe_tuple);

if (tmp_args_element_value_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 13;

    goto frame_exception_exit_1;
}
frame_frame_hello$$$function__3_main->m_frame.f_lineno = 13;
tmp_call_result_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_1, tmp_args_element_value_1);
CHECK_OBJECT(tmp_args_element_value_1);
Py_DECREF(tmp_args_element_value_1);
if (tmp_call_result_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 13;

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
tmp_called_value_4 = module_var_accessor_hello$fib(tstate);
if (unlikely(tmp_called_value_4 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_fib);
}

if (tmp_called_value_4 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));


exception_lineno = 14;

    goto frame_exception_exit_1;
}
frame_frame_hello$$$function__3_main->m_frame.f_lineno = 14;
tmp_args_element_value_2 = CALL_FUNCTION_WITH_POS_ARGS1(tstate, tmp_called_value_4, mod_consts.const_tuple_int_pos_20_tuple);

if (tmp_args_element_value_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 14;

    goto frame_exception_exit_1;
}
frame_frame_hello$$$function__3_main->m_frame.f_lineno = 14;
tmp_call_result_2 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, tmp_called_value_3, tmp_args_element_value_2);
CHECK_OBJECT(tmp_args_element_value_2);
Py_DECREF(tmp_args_element_value_2);
if (tmp_call_result_2 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 14;

    goto frame_exception_exit_1;
}
CHECK_OBJECT(tmp_call_result_2);
Py_DECREF(tmp_call_result_2);
}


popFrameStack(tstate);

goto frame_no_exception_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_hello$$$function__3_main, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_hello$$$function__3_main->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_hello$$$function__3_main, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}


Nuitka_Frame_AttachLocals(
    frame_frame_hello$$$function__3_main,
    type_description_1
);


if (frame_frame_hello$$$function__3_main == cache_frame_frame_hello$$$function__3_main) {
#if _DEBUG_REFCOUNTS
    count_active_frame_cache_instances -= 1;
    count_released_frame_cache_instances += 1;
#endif
    Py_DECREF(cache_frame_frame_hello$$$function__3_main);
    cache_frame_frame_hello$$$function__3_main = NULL;
}

assertFrameObject(frame_frame_hello$$$function__3_main);


popFrameStack(tstate);


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


   CHECK_OBJECT(tmp_return_value);
   assert(had_error || !HAS_ERROR_OCCURRED(tstate));
   return tmp_return_value;
}


static PyObject *MAKE_FUNCTION_hello$$$function__1_greet(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_hello$$$function__1_greet,
        mod_consts.const_str_plain_greet,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_4efcdcb3057fb04504680af5b1b5501d,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_hello,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}


static PyObject *MAKE_FUNCTION_hello$$$function__2_fib(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_hello$$$function__2_fib,
        mod_consts.const_str_plain_fib,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_e6de52e36e476551b386f8b9a74be9a3,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_hello,
        NULL,
        NULL,
        0
    );


    return (PyObject *)result;
}


static PyObject *MAKE_FUNCTION_hello$$$function__3_main(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_hello$$$function__3_main,
        mod_consts.const_str_plain_main,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_a8ac380f9efefefb6c4e470afd77f585,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_hello,
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


extern void registerDillPluginTables(PyThreadState *tstate, char const *module_name, PyMethodDef *reduce_compiled_function, PyMethodDef *create_compiled_function);

static function_impl_code const function_table_hello[] = {
impl_hello$$$function__1_greet,
impl_hello$$$function__2_fib,
impl_hello$$$function__3_main,
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

    return Nuitka_Function_GetFunctionState(function, function_table_hello);
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
        module_hello,
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
        function_table_hello,
        sizeof(function_table_hello) / sizeof(function_impl_code)
    );
}

static PyMethodDef _method_def_create_compiled_function = {
    "create_compiled_function",
    (PyCFunction)_create_compiled_function,
    METH_VARARGS, NULL
};


#endif


#if _NUITKA_MODULE_MODE && 1
static char const *module_full_name = "hello";
#endif


PyObject *module_code_hello(PyThreadState *tstate, PyObject *module, struct Nuitka_MetaPathBasedLoaderEntry const *loader_entry) {

    PGO_onModuleEntered("hello");


    module_hello = module;

    moduledict_hello = MODULE_DICT(module_hello);


    static bool init_done = false;

    if (init_done == false) {
#if _NUITKA_MODULE_MODE && 1


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
        PRINT_STRING("hello: Calling setupMetaPathBasedLoader().\n");
#endif
        setupMetaPathBasedLoader(tstate);
#if 0 >= 0
#ifdef _NUITKA_TRACE
        PRINT_STRING("hello: Calling updateMetaPathBasedLoaderModuleRoot().\n");
#endif
        updateMetaPathBasedLoaderModuleRoot(module_full_name);
#endif


#if PYTHON_VERSION >= 0x300
        patchInspectModule(tstate);
#endif

#endif

        /* The constants only used by this module are created now. */
        NUITKA_PRINT_TRACE("hello: Calling createModuleConstants().\n");
        createModuleConstants(tstate);

#if !defined(_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS)
        createModuleCodeObjects();
#endif
        init_done = true;
    }

#if _NUITKA_MODULE_MODE && 1
    PyObject *pre_load = IMPORT_EMBEDDED_MODULE(tstate, "hello" "-preLoad");
    if (pre_load == NULL) {
        return NULL;
    }
#endif

    // PRINT_STRING("in inithello\n");

#ifdef _NUITKA_PLUGIN_DILL_ENABLED
    {
        char const *module_name_c;
        if (loader_entry != NULL) {
            module_name_c = loader_entry->name;
        } else {
            PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___name__);
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
        moduledict_hello,
        (Nuitka_StringObject *)const_str_plain___compiled__,
        Nuitka_dunder_compiled_value
    );
#endif

    // Update "__package__" value to what it ought to be.
    {
#if 0
        UPDATE_STRING_DICT0(
            moduledict_hello,
            (Nuitka_StringObject *)const_str_plain___package__,
            const_str_empty
        );
#elif 0
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___name__);

        UPDATE_STRING_DICT0(
            moduledict_hello,
            (Nuitka_StringObject *)const_str_plain___package__,
            module_name
        );
#else

#if PYTHON_VERSION < 0x300
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___name__);
        char const *module_name_cstr = PyString_AS_STRING(module_name);

        char const *last_dot = strrchr(module_name_cstr, '.');

        if (last_dot != NULL) {
            UPDATE_STRING_DICT1(
                moduledict_hello,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyString_FromStringAndSize(module_name_cstr, last_dot - module_name_cstr)
            );
        }
#else
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___name__);
        Py_ssize_t dot_index = PyUnicode_Find(module_name, const_str_dot, 0, PyUnicode_GetLength(module_name), -1);

        if (dot_index != -1) {
            UPDATE_STRING_DICT1(
                moduledict_hello,
                (Nuitka_StringObject *)const_str_plain___package__,
                PyUnicode_Substring(module_name, 0, dot_index)
            );
        }
#endif
#endif
    }

    CHECK_OBJECT(module_hello);

    // For deep importing of a module we need to have "__builtins__", so we set
    // it ourselves in the same way than CPython does. Note: This must be done
    // before the frame object is allocated, or else it may fail.

    if (GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___builtins__) == NULL) {
        PyObject *value = (PyObject *)builtin_module;

        // Check if main module, not a dict then but the module itself.
#if _NUITKA_MODULE_MODE || !0
        value = PyModule_GetDict(value);
#endif

        UPDATE_STRING_DICT0(moduledict_hello, (Nuitka_StringObject *)const_str_plain___builtins__, value);
    }

    PyObject *module_loader = Nuitka_Loader_New(loader_entry);
    UPDATE_STRING_DICT0(moduledict_hello, (Nuitka_StringObject *)const_str_plain___loader__, module_loader);

#if PYTHON_VERSION >= 0x300
// Set the "__spec__" value

#if 0
    // Main modules just get "None" as spec.
    UPDATE_STRING_DICT0(moduledict_hello, (Nuitka_StringObject *)const_str_plain___spec__, Py_None);
#else
    // Other modules get a "ModuleSpec" from the standard mechanism.
    {
        PyObject *bootstrap_module = getImportLibBootstrapModule();
        CHECK_OBJECT(bootstrap_module);

        PyObject *_spec_from_module = PyObject_GetAttrString(bootstrap_module, "_spec_from_module");
        CHECK_OBJECT(_spec_from_module);

        PyObject *spec_value = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, _spec_from_module, module_hello);
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

        UPDATE_STRING_DICT1(moduledict_hello, (Nuitka_StringObject *)const_str_plain___spec__, spec_value);
    }
#endif
#endif

    // Temp variables if any
struct Nuitka_FrameObject *frame_frame_hello;
NUITKA_MAY_BE_UNUSED char const *type_description_1 = NULL;
bool tmp_result;
struct Nuitka_ExceptionPreservationItem exception_state = Empty_Nuitka_ExceptionPreservationItem;
NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Module init code if any


    // Module code.
{
PyObject *tmp_assign_source_1;
tmp_assign_source_1 = Py_None;
UPDATE_STRING_DICT0(moduledict_hello, (Nuitka_StringObject *)const_str_plain___doc__, tmp_assign_source_1);
}
{
PyObject *tmp_assign_source_2;
tmp_assign_source_2 = module_filename_obj;
UPDATE_STRING_DICT0(moduledict_hello, (Nuitka_StringObject *)const_str_plain___file__, tmp_assign_source_2);
}
frame_frame_hello = MAKE_MODULE_FRAME(code_objects_63ff75d9da1f95ed670f72b94af33f37, module_hello);

// Push the new frame as the currently active one, and we should be exclusively
// owning it.
pushFrameStackCompiledFrame(tstate, frame_frame_hello);
assert(Py_REFCNT(frame_frame_hello) == 2);

// Framed code:
{
PyObject *tmp_ass_attr_value_1;
PyObject *tmp_ass_attr_target_1;
tmp_ass_attr_value_1 = module_filename_obj;
tmp_ass_attr_target_1 = module_var_accessor_hello$__spec__(tstate);
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
tmp_ass_attr_target_2 = module_var_accessor_hello$__spec__(tstate);
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
UPDATE_STRING_DICT0(moduledict_hello, (Nuitka_StringObject *)const_str_plain___cached__, tmp_assign_source_3);
}
{
PyObject *tmp_assign_source_4;
tmp_assign_source_4 = Nuitka_dunder_compiled_value;
UPDATE_STRING_DICT0(moduledict_hello, (Nuitka_StringObject *)const_str_plain___compiled__, tmp_assign_source_4);
}
{
PyObject *tmp_assign_source_5;
PyObject *tmp_annotations_1;
tmp_annotations_1 = DICT_COPY(tstate, mod_consts.const_dict_0d747635c5b87742d1bd242db31edac3);

tmp_assign_source_5 = MAKE_FUNCTION_hello$$$function__1_greet(tstate, tmp_annotations_1);

UPDATE_STRING_DICT1(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_greet, tmp_assign_source_5);
}
{
PyObject *tmp_assign_source_6;
PyObject *tmp_annotations_2;
tmp_annotations_2 = DICT_COPY(tstate, mod_consts.const_dict_ac2d17ccf098d71f8de0232b23b5a904);

tmp_assign_source_6 = MAKE_FUNCTION_hello$$$function__2_fib(tstate, tmp_annotations_2);

UPDATE_STRING_DICT1(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_fib, tmp_assign_source_6);
}
{
PyObject *tmp_assign_source_7;
PyObject *tmp_annotations_3;
tmp_annotations_3 = DICT_COPY(tstate, mod_consts.const_dict_1259841a0de68bdf7d5f55bbd030b617);

tmp_assign_source_7 = MAKE_FUNCTION_hello$$$function__3_main(tstate, tmp_annotations_3);

UPDATE_STRING_DICT1(moduledict_hello, (Nuitka_StringObject *)mod_consts.const_str_plain_main, tmp_assign_source_7);
}
{
nuitka_bool tmp_condition_result_1;
PyObject *tmp_cmp_expr_left_1;
PyObject *tmp_cmp_expr_right_1;
tmp_cmp_expr_left_1 = module_var_accessor_hello$__name__(tstate);
assert(!(tmp_cmp_expr_left_1 == NULL));
tmp_cmp_expr_right_1 = mod_consts.const_str_plain___main__;
tmp_condition_result_1 = RICH_COMPARE_EQ_NBOOL_OBJECT_UNICODE(tmp_cmp_expr_left_1, tmp_cmp_expr_right_1);
if (tmp_condition_result_1 == NUITKA_BOOL_EXCEPTION) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 17;

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
PyObject *tmp_raise_type_1;
PyObject *tmp_make_exception_arg_1;
PyObject *tmp_called_value_1;
tmp_called_value_1 = module_var_accessor_hello$main(tstate);
if (unlikely(tmp_called_value_1 == NULL)) {
    RAISE_CURRENT_EXCEPTION_NAME_ERROR(tstate, &exception_state, mod_consts.const_str_plain_main);
}

if (tmp_called_value_1 == NULL) {
    assert(HAS_EXCEPTION_STATE(&exception_state));


exception_lineno = 18;

    goto frame_exception_exit_1;
}
frame_frame_hello->m_frame.f_lineno = 18;
tmp_make_exception_arg_1 = CALL_FUNCTION_NO_ARGS(tstate, tmp_called_value_1);
if (tmp_make_exception_arg_1 == NULL) {
    assert(HAS_ERROR_OCCURRED(tstate));

    FETCH_ERROR_OCCURRED_STATE(tstate, &exception_state);


exception_lineno = 18;

    goto frame_exception_exit_1;
}
frame_frame_hello->m_frame.f_lineno = 18;
tmp_raise_type_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, PyExc_SystemExit, tmp_make_exception_arg_1);
CHECK_OBJECT(tmp_make_exception_arg_1);
Py_DECREF(tmp_make_exception_arg_1);
assert(!(tmp_raise_type_1 == NULL));
exception_state.exception_value = tmp_raise_type_1;
exception_lineno = 18;
RAISE_EXCEPTION_WITH_VALUE(tstate, &exception_state);

goto frame_exception_exit_1;
}
branch_no_1:;


// Put the previous frame back on top.
popFrameStack(tstate);

goto frame_no_exception_1;
frame_exception_exit_1:


{
    PyTracebackObject *exception_tb = GET_EXCEPTION_STATE_TRACEBACK(&exception_state);
    if (exception_tb == NULL) {
        exception_tb = MAKE_TRACEBACK(frame_frame_hello, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    } else if (exception_tb->tb_frame != &frame_frame_hello->m_frame) {
        exception_tb = ADD_TRACEBACK(exception_tb, frame_frame_hello, exception_lineno);
        SET_EXCEPTION_STATE_TRACEBACK(&exception_state, exception_tb);
    }
}


assertFrameObject(frame_frame_hello);

// Put the previous frame back on top.
popFrameStack(tstate);

// Return the error.
goto module_exception_exit;
frame_no_exception_1:;

    // Report to PGO about leaving the module without error.
    PGO_onModuleExit("hello", false);

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *post_load = IMPORT_EMBEDDED_MODULE(tstate, "hello" "-postLoad");
        if (post_load == NULL) {
            return NULL;
        }
    }
#endif

    Py_INCREF(module_hello);
    return module_hello;
    module_exception_exit:

#if _NUITKA_MODULE_MODE && 1
    {
        PyObject *module_name = GET_STRING_DICT_VALUE(moduledict_hello, (Nuitka_StringObject *)const_str_plain___name__);

        if (module_name != NULL) {
            Nuitka_DelModule(tstate, module_name);
        }
    }
#endif
    PGO_onModuleExit("hello", false);

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
            moduledict_hello,
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
static struct PyModuleDef mdef_hello = {
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
            moduledict_hello,
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

static PyObject *PyInit_hello_phase2(PyObject *module) {
    PyThreadState *tstate = PyThreadState_GET();

    PyObject *result = module_code_hello(tstate, module, getLoaderEntry("hello"));

#if PYTHON_VERSION < 0x300


    if (HAS_ERROR_OCCURRED(tstate) == false) {
        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_hello, const_str_plain___file__);

        PyObject *fake_file_value = PyCObject_FromVoidPtr(NULL, onModuleFileValueRelease);

        UPDATE_STRING_DICT1(
            moduledict_hello,
            (Nuitka_StringObject *)const_str_plain___file__,
            fake_file_value
        );
    }
#else
    if (result != NULL) {


        orig_PyModule_Type_tp_setattro = PyModule_Type.tp_setattro;
        PyModule_Type.tp_setattro = Nuitka_TopLevelModule_tp_setattro;

        orig_dunder_file_value = DICT_GET_ITEM_WITH_HASH_ERROR1(tstate, (PyObject *)moduledict_hello, const_str_plain___file__);
    }
#endif

    return result;
}

#if 0 >= 0
static int PyInit_hello_slot(PyObject *module) {
    PyObject *result = PyInit_hello_phase2(module);

    if (unlikely(result == NULL)) {
        return 1;
    } else {
        return 0;
    }
}
#endif

NUITKA_MODULE_INIT_FUNCTION (PyInit_hello)(void) {
#if PYTHON_VERSION < 0x3c0
    if (_Py_PackageContext != NULL) {
        if (strcmp(module_full_name, _Py_PackageContext) != 0) {
            module_full_name = strdup(_Py_PackageContext);
        }
    }
#endif

#if PYTHON_VERSION < 0x300
    PyObject *module = Py_InitModule4(
        module_full_name,
        NULL,

        NULL,


        NULL,
        PYTHON_API_VERSION
    );
#else
    mdef_hello.m_name = module_full_name;

#if 0 == -1
    PyObject *module = PyModule_Create(&mdef_hello);
    CHECK_OBJECT(module);

    {
        NUITKA_MAY_BE_UNUSED bool res = Nuitka_SetModuleString(module_full_name, module);
        assert(res != false);
    }

#endif
#endif

#if 0 >= 0
    static PyModuleDef_Slot _module_slots[] = {
        {Py_mod_exec, (void *)PyInit_hello_slot},
        {0, NULL}
    };

    mdef_hello.m_slots = _module_slots;

    return PyModuleDef_Init(&mdef_hello);
#elif PYTHON_VERSION >= 0x300
    return PyInit_hello_phase2(module);
#else
    PyInit_hello_phase2(module);
#endif
}
