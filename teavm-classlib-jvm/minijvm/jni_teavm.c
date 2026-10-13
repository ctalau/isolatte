/*
 * Natives for running TeaVM's class library on miniJVM (isolatte teavm-classlib-jvm experiment).
 *
 * TeaVM's library leaves some methods to the backend: class metadata (ClassInfo, retargeted to
 * java.lang.Class as ci$* methods by the runtime builder), console output, a few math helpers.
 * The jail natives (org.isolatte.guest.Jail) are the guest's only access to host files: they take
 * virtual paths and confine them to the folder named by the ISOLATTE_JAIL environment variable.
 *
 * isolatte_native_allowed() is the allowlist find_native_method() consults: every entry of this
 * table, plus a fixed list of miniJVM's own std natives. miniJVM binds natives by class and method
 * name only, so without it any guest class named like a miniJVM class (org/mini/fs/..., sockets,
 * Runtime.exec, System.loadLibrary0) would get host access.
 */
#include <dirent.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "jvm.h"
#include "jvm_util.h"

/* miniJVM std natives reused under TeaVM names. */
s32 java_lang_Class_forName(Runtime *runtime, JClass *clazz);
s32 java_lang_Class_getPrimitiveClass(Runtime *runtime, JClass *clazz);

static JClass *this_class(Runtime *runtime) {
    return insOfJavaLangClass_get_classHandle(runtime, (Instance *) localvar_getRefer(runtime->localvar, 0));
}

static Instance *class_object(Runtime *runtime, JClass *cl) {
    return cl ? insOfJavaLangClass_create_get(runtime, cl) : NULL;
}

static s32 throw_npe(Runtime *runtime) {
    push_ref(runtime->stack, exception_create(JVM_EXCEPTION_NULLPOINTER, runtime));
    return RUNTIME_STATUS_EXCEPTION;
}

/* ------------------------------------------------------------------ ClassInfo (ci$) */

/* TeaVM's ModifiersInfo uses the JVM bits up to STRICT, then its own. */
static s32 teavm_modifiers(u16 jvm) {
    s32 m = jvm & 0x0FFF & ~0x0020; /* drop ACC_SUPER */
    if (jvm & 0x1000) m |= 1 << 15; /* SYNTHETIC */
    if (jvm & 0x2000) m |= 1 << 13; /* ANNOTATION */
    if (jvm & 0x4000) m |= 1 << 16; /* ENUM */
    return m;
}

static s32 ci_modifiers(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    s32 m;
    if (cl->is_primitive) m = 0x0411; /* public final abstract */
    else if (cl->mb.arr_type_index) m = 0x0411;
    else m = teavm_modifiers(cl->cff.access_flags);
    push_int(runtime->stack, m);
    return 0;
}

static s32 ci_primitiveKind(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    s32 kind = 0;
    if (cl->is_primitive) {
        static const c8 *names[] = {"boolean", "byte", "short", "char", "int", "long", "float", "double", "void"};
        s32 i;
        for (i = 0; i < 9; i++) {
            if (utf8_equals_c(cl->name, names[i])) kind = i + 1;
        }
    }
    push_int(runtime->stack, kind);
    return 0;
}

static s32 ci_name(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    Utf8String *ustr = utf8_create_copy(cl->name);
    utf8_replace_c(ustr, "/", ".");
    push_ref(runtime->stack, jstring_create(ustr, runtime));
    utf8_destroy(ustr);
    return 0;
}

static s32 ci_null(Runtime *runtime, JClass *clazz) {
    push_ref(runtime->stack, NULL);
    return 0;
}

static s32 ci_itemType(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    push_ref(runtime->stack, class_object(runtime, cl->mb.arr_type_index ? cl->component_class : NULL));
    return 0;
}

static JClass *array_of(Runtime *runtime, JClass *cl) {
    Utf8String *desc = utf8_create_c("[");
    if (cl->is_primitive) {
        static const c8 *names[] = {"boolean", "byte", "short", "char", "int", "long", "float", "double"};
        static const c8 tags[] = "ZBSCIJFD";
        s32 i;
        for (i = 0; i < 8; i++) {
            if (utf8_equals_c(cl->name, names[i])) utf8_pushback(desc, tags[i]);
        }
    } else if (cl->mb.arr_type_index) {
        utf8_append(desc, cl->name);
    } else {
        utf8_pushback(desc, 'L');
        utf8_append(desc, cl->name);
        utf8_pushback(desc, ';');
    }
    JClass *arr = desc->length > 1 ? array_class_create_get(runtime, cl->jloader, desc) : NULL;
    utf8_destroy(desc);
    return arr;
}

static s32 ci_arrayType(Runtime *runtime, JClass *clazz) {
    push_ref(runtime->stack, class_object(runtime, array_of(runtime, this_class(runtime))));
    return 0;
}

static s32 ci_isSuperTypeOf(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    JClass *sub = insOfJavaLangClass_get_classHandle(runtime, (Instance *) localvar_getRefer(runtime->localvar, 1));
    s32 r;
    if (cl->is_primitive || sub->is_primitive) r = cl == sub;
    else r = assignable_from(cl, sub);
    push_int(runtime->stack, r);
    return 0;
}

static s32 ci_parent(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    JClass *p = NULL;
    if (!cl->is_primitive && !(cl->cff.access_flags & ACC_INTERFACE && !cl->mb.arr_type_index)) p = getSuperClass(cl);
    push_ref(runtime->stack, class_object(runtime, p));
    return 0;
}

static s32 ci_superinterfaceCount(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    push_int(runtime->stack, cl->is_primitive || cl->mb.arr_type_index ? 0 : cl->interfacePool.clasz_used);
    return 0;
}

static s32 ci_superinterface(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    s32 i = localvar_getInt(runtime->localvar, 1);
    ConstantClassRef *ccr = cl->interfacePool.clasz + i;
    JClass *itf = classes_load_get_with_clinit(cl->jloader, class_get_constant_utf8(cl, ccr->stringIndex)->utfstr, runtime);
    push_ref(runtime->stack, class_object(runtime, itf));
    return 0;
}

/* Runs the enum's static values() and leaves the array on the stack. */
static s32 enum_values(Runtime *runtime, JClass *cl, Instance **out) {
    *out = NULL;
    if (!(cl->cff.access_flags & 0x4000) || cl->is_primitive || cl->mb.arr_type_index) return 0;
    Utf8String *name = utf8_create_c("values");
    Utf8String *desc = utf8_create_c("()[L");
    utf8_append(desc, cl->name);
    utf8_append_c(desc, ";");
    MethodInfo *mi = find_methodInfo_by_name(cl->name, name, desc, cl->jloader, runtime);
    utf8_destroy(name);
    utf8_destroy(desc);
    if (!mi) return 0;
    class_clinit(cl, runtime);
    s32 ret = execute_method_impl(mi, runtime);
    if (ret != RUNTIME_STATUS_NORMAL) return ret;
    *out = (Instance *) pop_ref(runtime->stack);
    return 0;
}

static s32 ci_enumConstantCount(Runtime *runtime, JClass *clazz) {
    Instance *arr;
    s32 ret = enum_values(runtime, this_class(runtime), &arr);
    if (ret) return ret;
    push_int(runtime->stack, arr ? jarray_length(arr) : 0);
    return 0;
}

static s32 ci_enumConstant(Runtime *runtime, JClass *clazz) {
    Instance *arr;
    s32 i = localvar_getInt(runtime->localvar, 1);
    s32 ret = enum_values(runtime, this_class(runtime), &arr);
    if (ret) return ret;
    push_ref(runtime->stack, arr ? (__refer) (intptr_t) jarray_get_field(arr, i) : NULL);
    return 0;
}

static s32 ci_newArrayInstance(Runtime *runtime, JClass *clazz) {
    JClass *arr = array_of(runtime, this_class(runtime));
    s32 n = localvar_getInt(runtime->localvar, 1);
    push_ref(runtime->stack, arr ? jarray_create_by_class(runtime, n, arr) : NULL);
    return 0;
}

static s32 ci_arrayLength(Runtime *runtime, JClass *clazz) {
    Instance *arr = (Instance *) localvar_getRefer(runtime->localvar, 1);
    if (!arr) return throw_npe(runtime);
    push_int(runtime->stack, jarray_length(arr));
    return 0;
}

/* Boxes array element i with the TeaVM box class's valueOf. */
static s32 ci_getItem(Runtime *runtime, JClass *clazz) {
    Instance *arr = (Instance *) localvar_getRefer(runtime->localvar, 1);
    s32 i = localvar_getInt(runtime->localvar, 2);
    if (!arr) return throw_npe(runtime);
    s32 t = arr->mb.arr_type_index;
    ShortCut *sc = &runtime->jvm->shortcut;
    s64 v = jarray_get_field(arr, i);
    MethodInfo *box = NULL;
    switch (t) {
        case DATATYPE_REFERENCE:
        case DATATYPE_ARRAY:
            push_ref(runtime->stack, (__refer) (intptr_t) v);
            return 0;
        case DATATYPE_BOOLEAN: push_int(runtime->stack, (s32) v); box = sc->boolean_valueOf; break;
        case DATATYPE_BYTE: push_int(runtime->stack, (s32) v); box = sc->byte_valueOf; break;
        case DATATYPE_SHORT: push_int(runtime->stack, (s32) v); box = sc->short_valueOf; break;
        case DATATYPE_JCHAR: push_int(runtime->stack, (s32) v); box = sc->character_valueOf; break;
        case DATATYPE_INT: push_int(runtime->stack, (s32) v); box = sc->int_valueOf; break;
        case DATATYPE_FLOAT: push_int(runtime->stack, (s32) v); box = sc->float_valueOf; break;
        case DATATYPE_LONG: push_long(runtime->stack, v); box = sc->long_valueOf; break;
        case DATATYPE_DOUBLE: push_long(runtime->stack, v); box = sc->double_valueOf; break;
    }
    if (!box) return throw_npe(runtime);
    return execute_method_impl(box, runtime);
}

static s32 ci_putItem(Runtime *runtime, JClass *clazz) {
    Instance *arr = (Instance *) localvar_getRefer(runtime->localvar, 1);
    s32 i = localvar_getInt(runtime->localvar, 2);
    Instance *val = (Instance *) localvar_getRefer(runtime->localvar, 3);
    if (!arr) return throw_npe(runtime);
    s32 t = arr->mb.arr_type_index;
    if (t == DATATYPE_REFERENCE || t == DATATYPE_ARRAY) {
        jarray_set_field(arr, i, (s64) (intptr_t) val);
        return 0;
    }
    if (!val) return throw_npe(runtime);
    /* All TeaVM boxes keep their primitive in a field named "value". */
    ShortCut *sc = &runtime->jvm->shortcut;
    FieldInfo *fi = NULL;
    switch (t) {
        case DATATYPE_BOOLEAN: fi = sc->boolean_value; break;
        case DATATYPE_BYTE: fi = sc->byte_value; break;
        case DATATYPE_SHORT: fi = sc->short_value; break;
        case DATATYPE_JCHAR: fi = sc->character_value; break;
        case DATATYPE_INT: fi = sc->int_value; break;
        case DATATYPE_FLOAT: fi = sc->float_value; break;
        case DATATYPE_LONG: fi = sc->long_value; break;
        case DATATYPE_DOUBLE: fi = sc->double_value; break;
    }
    if (!fi) return throw_npe(runtime);
    c8 *ptr = getInstanceFieldPtr(val, fi);
    s64 v;
    switch (t) {
        case DATATYPE_BOOLEAN:
        case DATATYPE_BYTE: v = getFieldByte(ptr); break;
        case DATATYPE_SHORT: v = getFieldShort(ptr); break;
        case DATATYPE_JCHAR: v = getFieldChar(ptr); break;
        case DATATYPE_LONG:
        case DATATYPE_DOUBLE: v = getFieldLong(ptr); break;
        default: v = getFieldInt(ptr); break;
    }
    jarray_set_field(arr, i, v);
    return 0;
}

static s32 ci_newInstance(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    Instance *ins = NULL;
    if (!cl->is_primitive && !cl->mb.arr_type_index && !(cl->cff.access_flags & (ACC_ABSTRACT | ACC_INTERFACE))) {
        class_clinit(cl, runtime);
        ins = instance_create(runtime, cl);
    }
    push_ref(runtime->stack, ins);
    return 0;
}

static s32 ci_initializeNewInstance(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    Instance *ins = (Instance *) localvar_getRefer(runtime->localvar, 1);
    Utf8String *name = utf8_create_c("<init>");
    Utf8String *desc = utf8_create_c("()V");
    MethodInfo *mi = find_methodInfo_by_name(cl->name, name, desc, cl->jloader, runtime);
    utf8_destroy(name);
    utf8_destroy(desc);
    if (!mi || mi->_this_class != cl) {
        push_int(runtime->stack, 0);
        return 0;
    }
    push_ref(runtime->stack, ins);
    s32 ret = execute_method_impl(mi, runtime);
    if (ret != RUNTIME_STATUS_NORMAL) return ret;
    push_int(runtime->stack, 1);
    return 0;
}

static s32 ci_initialize(Runtime *runtime, JClass *clazz) {
    JClass *cl = this_class(runtime);
    if (!cl->is_primitive && !cl->mb.arr_type_index) class_clinit(cl, runtime);
    return 0;
}

static s32 ci_classObject(Runtime *runtime, JClass *clazz) {
    push_ref(runtime->stack, localvar_getRefer(runtime->localvar, 0));
    return 0;
}

static s32 object_getObjectClassInfo(Runtime *runtime, JClass *clazz) {
    Instance *ins = (Instance *) localvar_getRefer(runtime->localvar, 0);
    if (!ins) return throw_npe(runtime);
    push_ref(runtime->stack, class_object(runtime, ins->mb.clazz));
    return 0;
}

/* ------------------------------------------------------------------ numbers */

typedef union { s64 l; f64 d; } L2D;
typedef union { s32 i; f32 f; } I2F;

static f64 arg_double(Runtime *runtime, s32 slot) {
    L2D u;
    u.l = localvar_getLong(runtime->localvar, slot);
    return u.d;
}

static f32 arg_float(Runtime *runtime, s32 slot) {
    I2F u;
    u.i = localvar_getInt(runtime->localvar, slot);
    return u.f;
}

static s32 double_doubleToRawLongBits(Runtime *runtime, JClass *clazz) {
    push_long(runtime->stack, localvar_getLong(runtime->localvar, 0));
    return 0;
}

static s32 double_isNaN(Runtime *runtime, JClass *clazz) {
    push_int(runtime->stack, isnan(arg_double(runtime, 0)) ? 1 : 0);
    return 0;
}

static s32 double_isFinite(Runtime *runtime, JClass *clazz) {
    push_int(runtime->stack, isfinite(arg_double(runtime, 0)) ? 1 : 0);
    return 0;
}

static s32 float_floatToRawIntBits(Runtime *runtime, JClass *clazz) {
    push_int(runtime->stack, localvar_getInt(runtime->localvar, 0));
    return 0;
}

static s32 float_isNaN(Runtime *runtime, JClass *clazz) {
    push_int(runtime->stack, isnan(arg_float(runtime, 0)) ? 1 : 0);
    return 0;
}

static s32 float_isFinite(Runtime *runtime, JClass *clazz) {
    push_int(runtime->stack, isfinite(arg_float(runtime, 0)) ? 1 : 0);
    return 0;
}

static s32 int_compare(Runtime *runtime, JClass *clazz) {
    s32 a = localvar_getInt(runtime->localvar, 0), b = localvar_getInt(runtime->localvar, 1);
    push_int(runtime->stack, a < b ? -1 : a > b ? 1 : 0);
    return 0;
}

static s32 int_compareUnsigned(Runtime *runtime, JClass *clazz) {
    u32 a = (u32) localvar_getInt(runtime->localvar, 0), b = (u32) localvar_getInt(runtime->localvar, 1);
    push_int(runtime->stack, a < b ? -1 : a > b ? 1 : 0);
    return 0;
}

static s32 int_divideUnsigned(Runtime *runtime, JClass *clazz) {
    u32 a = (u32) localvar_getInt(runtime->localvar, 0), b = (u32) localvar_getInt(runtime->localvar, 1);
    if (!b) {
        push_ref(runtime->stack, exception_create(JVM_EXCEPTION_ARRITHMETIC, runtime));
        return RUNTIME_STATUS_EXCEPTION;
    }
    push_int(runtime->stack, (s32) (a / b));
    return 0;
}

static s32 int_remainderUnsigned(Runtime *runtime, JClass *clazz) {
    u32 a = (u32) localvar_getInt(runtime->localvar, 0), b = (u32) localvar_getInt(runtime->localvar, 1);
    if (!b) {
        push_ref(runtime->stack, exception_create(JVM_EXCEPTION_ARRITHMETIC, runtime));
        return RUNTIME_STATUS_EXCEPTION;
    }
    push_int(runtime->stack, (s32) (a % b));
    return 0;
}

static s32 long_compare(Runtime *runtime, JClass *clazz) {
    s64 a = localvar_getLong(runtime->localvar, 0), b = localvar_getLong(runtime->localvar, 2);
    push_int(runtime->stack, a < b ? -1 : a > b ? 1 : 0);
    return 0;
}

static s32 long_compareUnsigned(Runtime *runtime, JClass *clazz) {
    u64 a = (u64) localvar_getLong(runtime->localvar, 0), b = (u64) localvar_getLong(runtime->localvar, 2);
    push_int(runtime->stack, a < b ? -1 : a > b ? 1 : 0);
    return 0;
}

static s32 long_divideUnsigned(Runtime *runtime, JClass *clazz) {
    u64 a = (u64) localvar_getLong(runtime->localvar, 0), b = (u64) localvar_getLong(runtime->localvar, 2);
    if (!b) {
        push_ref(runtime->stack, exception_create(JVM_EXCEPTION_ARRITHMETIC, runtime));
        return RUNTIME_STATUS_EXCEPTION;
    }
    push_long(runtime->stack, (s64) (a / b));
    return 0;
}

static s32 long_remainderUnsigned(Runtime *runtime, JClass *clazz) {
    u64 a = (u64) localvar_getLong(runtime->localvar, 0), b = (u64) localvar_getLong(runtime->localvar, 2);
    if (!b) {
        push_ref(runtime->stack, exception_create(JVM_EXCEPTION_ARRITHMETIC, runtime));
        return RUNTIME_STATUS_EXCEPTION;
    }
    push_long(runtime->stack, (s64) (a % b));
    return 0;
}

static s32 math_minDD(Runtime *runtime, JClass *clazz) {
    push_float(runtime->stack, (f32) fmin(arg_double(runtime, 0), arg_double(runtime, 2)));
    return 0;
}

static s32 math_maxDD(Runtime *runtime, JClass *clazz) {
    push_float(runtime->stack, (f32) fmax(arg_double(runtime, 0), arg_double(runtime, 2)));
    return 0;
}

static s32 math_minFF(Runtime *runtime, JClass *clazz) {
    push_float(runtime->stack, fminf(arg_float(runtime, 0), arg_float(runtime, 1)));
    return 0;
}

static s32 math_maxFF(Runtime *runtime, JClass *clazz) {
    push_float(runtime->stack, fmaxf(arg_float(runtime, 0), arg_float(runtime, 1)));
    return 0;
}

static s32 math_absF(Runtime *runtime, JClass *clazz) {
    push_float(runtime->stack, fabsf(arg_float(runtime, 0)));
    return 0;
}

static s32 math_absD(Runtime *runtime, JClass *clazz) {
    push_double(runtime->stack, fabs(arg_double(runtime, 0)));
    return 0;
}

static s32 math_signD(Runtime *runtime, JClass *clazz) {
    f64 d = arg_double(runtime, 0);
    push_double(runtime->stack, d > 0 ? 1.0 : d < 0 ? -1.0 : d);
    return 0;
}

static s32 math_signF(Runtime *runtime, JClass *clazz) {
    f32 f = arg_float(runtime, 0);
    push_float(runtime->stack, f > 0 ? 1.0f : f < 0 ? -1.0f : f);
    return 0;
}

static s32 math_pow(Runtime *runtime, JClass *clazz) {
    push_double(runtime->stack, pow(arg_double(runtime, 0), arg_double(runtime, 2)));
    return 0;
}

/* ------------------------------------------------------------------ console */

static s32 console_write(Runtime *runtime, FILE *f) {
    Instance *arr = (Instance *) localvar_getRefer(runtime->localvar, 0);
    s32 off = localvar_getInt(runtime->localvar, 1);
    s32 len = localvar_getInt(runtime->localvar, 2);
    if (!arr) return throw_npe(runtime);
    if (off < 0 || len < 0 || off + len > jarray_length(arr)) {
        push_ref(runtime->stack, exception_create(JVM_EXCEPTION_ARRAYINDEXOUTOFBOUNDS, runtime));
        return RUNTIME_STATUS_EXCEPTION;
    }
    fwrite(jarray_body(arr) + off, 1, (size_t) len, f);
    fflush(f);
    return 0;
}

static s32 console_writeStdout(Runtime *runtime, JClass *clazz) {
    return console_write(runtime, stdout);
}

static s32 console_writeStderr(Runtime *runtime, JClass *clazz) {
    return console_write(runtime, stderr);
}

/* ------------------------------------------------------------------ class path resources */

/* Guest-supplied names must not leave the boot class path: no absolute paths, no "." or ".." or
 * empty segments. (miniJVM resolves directory entries by string concatenation.) */
static s32 plain_path(const c8 *p) {
    if (!*p || *p == '/') return 0;
    const c8 *seg = p;
    for (;;) {
        const c8 *end = strchr(seg, '/');
        size_t n = end ? (size_t) (end - seg) : strlen(seg);
        if (n == 0 || (n == 1 && seg[0] == '.') || (n == 2 && seg[0] == '.' && seg[1] == '.')) return 0;
        if (memchr(seg, '\\', n)) return 0;
        if (!end) return 1;
        seg = end + 1;
    }
}

static Instance *byte_array(Runtime *runtime, const c8 *data, s32 len) {
    Instance *arr = jarray_create_by_type_index(runtime, len, DATATYPE_BYTE);
    if (arr && len) memcpy(jarray_body(arr), data, (size_t) len);
    return arr;
}

static s32 resources_read(Runtime *runtime, JClass *clazz) {
    Instance *jstr = (Instance *) localvar_getRefer(runtime->localvar, 0);
    if (!jstr) return throw_npe(runtime);
    Utf8String *path = utf8_create();
    jstring_2_utf8(jstr, path, runtime);
    Instance *arr = NULL;
    if (plain_path(utf8_cstr(path))) {
        ByteBuf *buf = load_file_from_classpath(runtime->jvm->boot_classloader, path);
        if (buf) {
            arr = jarray_create_by_type_index(runtime, buf->wp, DATATYPE_BYTE);
            if (arr) bytebuf_read_batch(buf, jarray_body(arr), buf->wp);
            bytebuf_destroy(buf);
        }
    }
    utf8_destroy(path);
    push_ref(runtime->stack, arr);
    return 0;
}

/* ------------------------------------------------------------------ jail */

#define JAIL_EXISTS 1
#define JAIL_REGULAR 2
#define JAIL_DIRECTORY 4

/* The real host path of a virtual path, or 0 when it is outside the jail or does not exist.
 * ".." is resolved lexically first (it stops at "/"), then realpath(3) follows symlinks and the
 * result must still be inside the jail folder. */
static s32 jail_resolve(Runtime *runtime, Instance *jstr, c8 *out) {
    c8 root[PATH_MAX];
    const c8 *env = getenv("ISOLATTE_JAIL");
    if (!jstr || !env || !realpath(env, root)) return 0;
    Utf8String *u = utf8_create();
    jstring_2_utf8(jstr, u, runtime);
    const c8 *v = utf8_cstr(u);
    c8 joined[PATH_MAX * 2];
    size_t rootlen = strlen(root), len = rootlen;
    memcpy(joined, root, rootlen + 1);
    const c8 *seg = v;
    s32 ok = 1;
    while (*seg && ok) {
        while (*seg == '/') seg++;
        const c8 *end = strchr(seg, '/');
        size_t n = end ? (size_t) (end - seg) : strlen(seg);
        if (n == 0 || (n == 1 && seg[0] == '.')) {
        } else if (n == 2 && seg[0] == '.' && seg[1] == '.') {
            while (len > rootlen && joined[len - 1] != '/') len--;
            if (len > rootlen) len--;
            joined[len] = 0;
        } else if (memchr(seg, 0, n) || len + 1 + n >= sizeof(joined)) {
            ok = 0;
        } else {
            joined[len++] = '/';
            memcpy(joined + len, seg, n);
            len += n;
            joined[len] = 0;
        }
        seg += n;
    }
    utf8_destroy(u);
    if (!ok || !realpath(joined, out)) return 0;
    size_t outlen = strlen(out);
    if (outlen < rootlen || strncmp(out, root, rootlen) != 0 || (out[rootlen] != 0 && out[rootlen] != '/')) return 0;
    return 1;
}

static s32 jail_attributes(Runtime *runtime, JClass *clazz) {
    c8 p[PATH_MAX];
    struct stat st;
    s32 r = 0;
    if (jail_resolve(runtime, localvar_getRefer(runtime->localvar, 0), p) && stat(p, &st) == 0) {
        r = JAIL_EXISTS | (S_ISREG(st.st_mode) ? JAIL_REGULAR : 0) | (S_ISDIR(st.st_mode) ? JAIL_DIRECTORY : 0);
    }
    push_int(runtime->stack, r);
    return 0;
}

static s32 jail_length(Runtime *runtime, JClass *clazz) {
    c8 p[PATH_MAX];
    struct stat st;
    s64 r = 0;
    if (jail_resolve(runtime, localvar_getRefer(runtime->localvar, 0), p) && stat(p, &st) == 0) r = st.st_size;
    push_long(runtime->stack, r);
    return 0;
}

static s32 jail_lastModified(Runtime *runtime, JClass *clazz) {
    c8 p[PATH_MAX];
    struct stat st;
    s64 r = 0;
    if (jail_resolve(runtime, localvar_getRefer(runtime->localvar, 0), p) && stat(p, &st) == 0) r = (s64) st.st_mtime * 1000;
    push_long(runtime->stack, r);
    return 0;
}

static s32 jail_list(Runtime *runtime, JClass *clazz) {
    c8 p[PATH_MAX];
    DIR *d;
    if (!jail_resolve(runtime, localvar_getRefer(runtime->localvar, 0), p) || !(d = opendir(p))) {
        push_ref(runtime->stack, NULL);
        return 0;
    }
    s32 n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    }
    rewinddir(d);
    Utf8String *type = utf8_create_c(STR_INS_JAVA_LANG_STRING);
    Instance *arr = jarray_create_by_type_name(runtime, n, type, NULL);
    utf8_destroy(type);
    if (!arr || instance_hold_to_thread(arr, runtime) != 0) {
        closedir(d);
        return exception_throw_out_of_memory(runtime);
    }
    s32 i = 0;
    while ((e = readdir(d)) && i < n) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        Utf8String *name = utf8_create_c(e->d_name);
        jarray_set_field(arr, i++, (s64) (intptr_t) jstring_create(name, runtime));
        utf8_destroy(name);
    }
    closedir(d);
    instance_release_from_thread(arr, runtime);
    push_ref(runtime->stack, arr);
    return 0;
}

static s32 jail_read(Runtime *runtime, JClass *clazz) {
    c8 p[PATH_MAX];
    struct stat st;
    FILE *f;
    if (!jail_resolve(runtime, localvar_getRefer(runtime->localvar, 0), p) || stat(p, &st) != 0 || !S_ISREG(st.st_mode)
        || st.st_size > 0x7fffffff || !(f = fopen(p, "rb"))) {
        push_ref(runtime->stack, NULL);
        return 0;
    }
    s32 len = (s32) st.st_size;
    Instance *arr = jarray_create_by_type_index(runtime, len, DATATYPE_BYTE);
    if (arr && len && fread(jarray_body(arr), 1, (size_t) len, f) != (size_t) len) arr = NULL;
    fclose(f);
    push_ref(runtime->stack, arr);
    return 0;
}

/* ------------------------------------------------------------------ boot */

static s32 boot_callMain(Runtime *runtime, JClass *clazz) {
    JClass *cl = insOfJavaLangClass_get_classHandle(runtime, (Instance *) localvar_getRefer(runtime->localvar, 0));
    Instance *args = (Instance *) localvar_getRefer(runtime->localvar, 1);
    Utf8String *name = utf8_create_c("main");
    Utf8String *desc = utf8_create_c("([Ljava/lang/String;)V");
    MethodInfo *mi = cl ? find_methodInfo_by_name(cl->name, name, desc, cl->jloader, runtime) : NULL;
    utf8_destroy(name);
    utf8_destroy(desc);
    if (!mi || !(mi->access_flags & ACC_STATIC)) {
        push_ref(runtime->stack, exception_create_str(JVM_EXCEPTION_NOSUCHMETHOD, runtime, "main"));
        return RUNTIME_STATUS_EXCEPTION;
    }
    class_clinit(cl, runtime);
    push_ref(runtime->stack, args);
    return execute_method_impl(mi, runtime);
}

/* ------------------------------------------------------------------ table */

#define CI "java/lang/Class"
static java_native_method METHODS_TEAVM_TABLE[] = {
    {CI, "ci$modifiers", "()I", ci_modifiers},
    {CI, "ci$primitiveKind", "()I", ci_primitiveKind},
    {CI, "ci$name", "()Ljava/lang/String;", ci_name},
    {CI, "ci$simpleName", "()Ljava/lang/String;", ci_null},
    {CI, "ci$itemType", "()Ljava/lang/Class;", ci_itemType},
    {CI, "ci$arrayType", "()Ljava/lang/Class;", ci_arrayType},
    {CI, "ci$declaringClass", "()Ljava/lang/Class;", ci_null},
    {CI, "ci$enclosingClass", "()Ljava/lang/Class;", ci_null},
    {CI, "ci$isSuperTypeOf", "(Ljava/lang/Class;)Z", ci_isSuperTypeOf},
    {CI, "ci$parent", "()Ljava/lang/Class;", ci_parent},
    {CI, "ci$superinterfaceCount", "()I", ci_superinterfaceCount},
    {CI, "ci$superinterface", "(I)Ljava/lang/Class;", ci_superinterface},
    {CI, "ci$enumConstantCount", "()I", ci_enumConstantCount},
    {CI, "ci$enumConstant", "(I)Ljava/lang/Object;", ci_enumConstant},
    {CI, "ci$newArrayInstance", "(I)Ljava/lang/Object;", ci_newArrayInstance},
    {CI, "ci$putItem", "(Ljava/lang/Object;ILjava/lang/Object;)V", ci_putItem},
    {CI, "ci$getItem", "(Ljava/lang/Object;I)Ljava/lang/Object;", ci_getItem},
    {CI, "ci$arrayLength", "(Ljava/lang/Object;)I", ci_arrayLength},
    {CI, "ci$newInstance", "()Ljava/lang/Object;", ci_newInstance},
    {CI, "ci$initializeNewInstance", "(Ljava/lang/Object;)Z", ci_initializeNewInstance},
    {CI, "ci$initialize", "()V", ci_initialize},
    {CI, "ci$reflection", "()Lorg/teavm/runtime/reflect/ClassReflectionInfo;", ci_null},
    {CI, "ci$classObject", "()Ljava/lang/Class;", ci_classObject},
    {CI, "vm$forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", java_lang_Class_forName},
    {CI, "vm$getPrimitiveClass", "(Ljava/lang/String;)Ljava/lang/Class;", java_lang_Class_getPrimitiveClass},
    {"java/lang/Object", "getObjectClassInfo", "(Ljava/lang/Object;)Ljava/lang/Class;", object_getObjectClassInfo},
    {"java/lang/Double", "doubleToRawLongBits", "(D)J", double_doubleToRawLongBits},
    {"java/lang/Double", "isNaN", "(D)Z", double_isNaN},
    {"java/lang/Double", "isFinite", "(D)Z", double_isFinite},
    {"java/lang/Float", "floatToRawIntBits", "(F)I", float_floatToRawIntBits},
    {"java/lang/Float", "isNaN", "(F)Z", float_isNaN},
    {"java/lang/Float", "isFinite", "(F)Z", float_isFinite},
    {"java/lang/Integer", "compare", "(II)I", int_compare},
    {"java/lang/Integer", "compareUnsigned", "(II)I", int_compareUnsigned},
    {"java/lang/Integer", "divideUnsigned", "(II)I", int_divideUnsigned},
    {"java/lang/Integer", "remainderUnsigned", "(II)I", int_remainderUnsigned},
    {"java/lang/Long", "compare", "(JJ)I", long_compare},
    {"java/lang/Long", "compareUnsigned", "(JJ)I", long_compareUnsigned},
    {"java/lang/Long", "divideUnsigned", "(JJ)J", long_divideUnsigned},
    {"java/lang/Long", "remainderUnsigned", "(JJ)J", long_remainderUnsigned},
    {"java/lang/Math", "minImpl", "(DD)F", math_minDD},
    {"java/lang/Math", "maxImpl", "(DD)F", math_maxDD},
    {"java/lang/Math", "minImpl", "(FF)F", math_minFF},
    {"java/lang/Math", "maxImpl", "(FF)F", math_maxFF},
    {"java/lang/Math", "absImpl", "(F)F", math_absF},
    {"java/lang/Math", "absImpl", "(D)D", math_absD},
    {"java/lang/Math", "sign", "(D)D", math_signD},
    {"java/lang/Math", "sign", "(F)F", math_signF},
    {"java/lang/Math", "powImpl", "(DD)D", math_pow},
    {"org/teavm/classlib/impl/console/Console", "writeStdout", "([BII)V", console_writeStdout},
    {"org/teavm/classlib/impl/console/Console", "writeStderr", "([BII)V", console_writeStderr},
    {"org/isolatte/guest/Boot", "callMain", "(Ljava/lang/Class;[Ljava/lang/String;)V", boot_callMain},
    {"org/isolatte/guest/Resources", "read", "(Ljava/lang/String;)[B", resources_read},
    {"org/isolatte/guest/Jail", "attributes", "(Ljava/lang/String;)I", jail_attributes},
    {"org/isolatte/guest/Jail", "list", "(Ljava/lang/String;)[Ljava/lang/String;", jail_list},
    {"org/isolatte/guest/Jail", "length", "(Ljava/lang/String;)J", jail_length},
    {"org/isolatte/guest/Jail", "lastModified", "(Ljava/lang/String;)J", jail_lastModified},
    {"org/isolatte/guest/Jail", "read", "(Ljava/lang/String;)[B", jail_read},
};

/* miniJVM std natives the TeaVM classes are bound to (their methods are made native by the
 * runtime builder). Nothing that touches files, sockets, processes or native libraries. */
static const c8 *STD_ALLOWED[][2] = {
    {"java/lang/Object", "clone"},
    {"java/lang/Object", "notify"},
    {"java/lang/Object", "notifyAll"},
    {"java/lang/Object", "wait"},
    {"java/lang/System", "arraycopy"},
    {"java/lang/System", "currentTimeMillis"},
    {"java/lang/System", "nanoTime"},
    {"java/lang/System", "identityHashCode"},
    {"java/lang/String", "intern0"},
    {"java/lang/Double", "longBitsToDouble"},
    {"java/lang/Float", "intBitsToFloat"},
    {"java/lang/Math", "sin"}, {"java/lang/Math", "cos"}, {"java/lang/Math", "tan"},
    {"java/lang/Math", "asin"}, {"java/lang/Math", "acos"}, {"java/lang/Math", "atan"},
    {"java/lang/Math", "atan2"}, {"java/lang/Math", "exp"}, {"java/lang/Math", "log"},
    {"java/lang/Math", "sqrt"}, {"java/lang/Math", "ceil"}, {"java/lang/Math", "floor"},
    {"java/lang/Math", "random"},
    {"java/lang/Throwable", "buildStackElement"},
};

s32 isolatte_native_allowed(java_native_method *m) {
    if (m >= METHODS_TEAVM_TABLE && m < METHODS_TEAVM_TABLE + sizeof(METHODS_TEAVM_TABLE) / sizeof(java_native_method)) {
        return 1;
    }
    size_t i;
    for (i = 0; i < sizeof(STD_ALLOWED) / sizeof(STD_ALLOWED[0]); i++) {
        if (!strcmp(m->clzname, STD_ALLOWED[i][0]) && !strcmp(m->methodname, STD_ALLOWED[i][1])) return 1;
    }
    return 0;
}

void reg_teavm_native_lib(MiniJVM *jvm) {
    native_reg_lib(jvm, &(METHODS_TEAVM_TABLE[0]), sizeof(METHODS_TEAVM_TABLE) / sizeof(java_native_method));
}
