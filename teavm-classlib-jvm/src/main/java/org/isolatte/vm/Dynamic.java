package org.isolatte.vm;

import static org.objectweb.asm.Opcodes.*;

import java.util.ArrayList;
import java.util.List;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;

/**
 * invokedynamic, for the two bootstrap methods javac emits in this code: lambdas/method references
 * ({@code LambdaMetafactory}) and string concatenation ({@code StringConcatFactory}). Both are
 * linked by the VM instead of running a guest bootstrap method, as TeaVM's compiler also does.
 * String concatenation formats every value with the guest's {@code String.valueOf}, so the result
 * is what TeaVM's class library produces.
 */
final class Dynamic {
    private Dynamic() {
    }

    static VM.Linked link(VM vm, VMethod caller, InvokeDynamicInsnNode indy) {
        Handle bsm = indy.bsm;
        Type type = Type.getMethodType(indy.desc);
        int argc = type.getArgumentTypes().length;
        switch (bsm.getOwner() + "." + bsm.getName()) {
            case "java/lang/invoke/LambdaMetafactory.metafactory":
            case "java/lang/invoke/LambdaMetafactory.altMetafactory":
                return lambda(vm, caller, indy, type, argc);
            case "java/lang/invoke/StringConcatFactory.makeConcatWithConstants":
                return concat(vm, type, (String) indy.bsmArgs[0], indy.bsmArgs, argc);
            case "java/lang/invoke/StringConcatFactory.makeConcat":
                return concat(vm, type, "\u0001".repeat(argc), new Object[0], argc);
            default:
                throw vm.error("java/lang/BootstrapMethodError", "unsupported bootstrap " + bsm.getOwner() + "." + bsm.getName());
        }
    }

    private static VM.Linked concat(VM vm, Type type, String recipe, Object[] bsmArgs, int argc) {
        Type[] argTypes = type.getArgumentTypes();
        String[] valueOf = new String[argc];
        for (int i = 0; i < argc; i++) {
            valueOf[i] = switch (argTypes[i].getSort()) {
                case Type.BOOLEAN -> "valueOf(Z)Ljava/lang/String;";
                case Type.CHAR -> "valueOf(C)Ljava/lang/String;";
                case Type.BYTE, Type.SHORT, Type.INT -> "valueOf(I)Ljava/lang/String;";
                case Type.LONG -> "valueOf(J)Ljava/lang/String;";
                case Type.FLOAT -> "valueOf(F)Ljava/lang/String;";
                case Type.DOUBLE -> "valueOf(D)Ljava/lang/String;";
                default -> "valueOf(Ljava/lang/Object;)Ljava/lang/String;";
            };
        }
        return new VM.Linked(argc, false) {
            @Override
            Object call(VM vm, Object[] args) {
                StringBuilder sb = new StringBuilder();
                int arg = 0;
                int cst = 1;
                for (int i = 0; i < recipe.length(); i++) {
                    char c = recipe.charAt(i);
                    if (c == '\u0001') {
                        sb.append(VM.host(vm.callStatic("java/lang/String", valueOf[arg], args[arg])));
                        arg++;
                    } else if (c == '\u0002') {
                        sb.append(bsmArgs[cst++]);
                    } else {
                        sb.append(c);
                    }
                }
                return vm.str(sb.toString());
            }
        };
    }

    private static VM.Linked lambda(VM vm, VMethod caller, InvokeDynamicInsnNode indy, Type type, int argc) {
        Object[] a = indy.bsmArgs;
        Type samType = (Type) a[0];
        Handle impl = (Handle) a[1];
        Type instantiated = (Type) a[2];
        List<VClass> ifaces = new ArrayList<>();
        ifaces.add(vm.load(type.getReturnType().getInternalName()));
        List<String> descs = new ArrayList<>();
        descs.add(samType.getDescriptor());
        if (indy.bsm.getName().equals("altMetafactory")) {
            int flags = (Integer) a[3];
            int i = 4;
            if ((flags & 2) != 0) { // FLAG_MARKERS
                int n = (Integer) a[i++];
                for (int k = 0; k < n; k++) {
                    ifaces.add(vm.load(((Type) a[i++]).getInternalName()));
                }
            }
            if ((flags & 4) != 0) { // FLAG_BRIDGES
                int n = (Integer) a[i++];
                for (int k = 0; k < n; k++) {
                    descs.add(((Type) a[i++]).getDescriptor());
                }
            }
        }
        String name = caller.owner.name + "$$Lambda$" + (++vm.lambdaCount);
        Type[] captured = type.getArgumentTypes();
        java.util.Map<String, Native> impls = new java.util.LinkedHashMap<>();
        for (String d : descs) {
            Type mt = Type.getMethodType(d);
            impls.put(indy.name + d, args -> {
                Object[] caps = (Object[]) ((VObject) args[0]).hidden;
                Object[] all = new Object[caps.length + args.length - 1];
                System.arraycopy(caps, 0, all, 0, caps.length);
                System.arraycopy(args, 1, all, caps.length, args.length - 1);
                Type[] from = new Type[all.length];
                System.arraycopy(captured, 0, from, 0, captured.length);
                System.arraycopy(mt.getArgumentTypes(), 0, from, captured.length, mt.getArgumentTypes().length);
                Object r = callImpl(vm, impl, all, from);
                return adapt(vm, r, implReturn(impl), mt.getReturnType());
            });
        }
        VClass cls = vm.synthetic(name, ifaces, impls, caller.owner.sourceFile);
        return new VM.Linked(argc, false) {
            @Override
            Object call(VM vm, Object[] args) {
                VObject o = new VObject(cls);
                o.hidden = args.clone();
                return o;
            }
        };
    }

    private static Type implReturn(Handle h) {
        return h.getTag() == H_NEWINVOKESPECIAL ? Type.getObjectType(h.getOwner()) : Type.getReturnType(h.getDesc());
    }

    private static Object callImpl(VM vm, Handle h, Object[] all, Type[] from) {
        VClass owner = vm.load(h.getOwner());
        Type[] params = Type.getArgumentTypes(h.getDesc());
        String nd = h.getName() + h.getDesc();
        switch (h.getTag()) {
            case H_INVOKESTATIC: {
                Object[] args = new Object[params.length];
                for (int i = 0; i < params.length; i++) {
                    args[i] = adapt(vm, all[i], from[i], params[i]);
                }
                vm.initialize(owner);
                return vm.invoke(vm.findMethod(owner, nd), args);
            }
            case H_NEWINVOKESPECIAL: {
                Object[] args = new Object[params.length + 1];
                VObject o = vm.newObject(owner);
                args[0] = o;
                for (int i = 0; i < params.length; i++) {
                    args[i + 1] = adapt(vm, all[i], from[i], params[i]);
                }
                vm.invoke(vm.findMethod(owner, nd), args);
                return o;
            }
            default: {
                Object[] args = new Object[params.length + 1];
                args[0] = all[0];
                if (args[0] == null) {
                    throw vm.error("java/lang/NullPointerException", null);
                }
                for (int i = 0; i < params.length; i++) {
                    args[i + 1] = adapt(vm, all[i + 1], from[i + 1], params[i]);
                }
                VMethod target = h.getTag() == H_INVOKESPECIAL ? vm.findMethod(owner, nd) : vm.virtualMethod(vm.classOf(args[0]), nd);
                return vm.invoke(target, args);
            }
        }
    }

    private static boolean primitive(Type t) {
        return t.getSort() < Type.ARRAY;
    }

    /** Boxing, unboxing and primitive widening between a lambda's interface and implementation types. */
    static Object adapt(VM vm, Object v, Type from, Type to) {
        if (to.getSort() == Type.VOID) {
            return null;
        }
        boolean fp = primitive(from);
        boolean tp = primitive(to);
        if (!fp && !tp) {
            return v;
        }
        if (fp && !tp) {
            return box(vm, v, from);
        }
        if (!fp) {
            if (v == null) {
                throw vm.error("java/lang/NullPointerException", null);
            }
            Type boxed = unboxedType(((VObject) v).cls.name);
            v = vm.callVirtual(boxed.getClassName() + "Value()" + boxed.getDescriptor(), v);
            from = boxed;
        }
        return widen(v, from, to);
    }

    private static Object widen(Object v, Type from, Type to) {
        if (from.getSort() == to.getSort()) {
            return v;
        }
        double d = v instanceof Integer i ? i : v instanceof Long l ? l : v instanceof Float f ? f : (Double) v;
        return switch (to.getSort()) {
            case Type.LONG -> v instanceof Integer i ? (long) i : (long) d;
            case Type.FLOAT -> v instanceof Long l ? (float) l : (float) d;
            case Type.DOUBLE -> v instanceof Long l ? (double) l : d;
            default -> v;
        };
    }

    private static Type unboxedType(String boxClass) {
        return switch (boxClass) {
            case "java/lang/Integer" -> Type.INT_TYPE;
            case "java/lang/Long" -> Type.LONG_TYPE;
            case "java/lang/Boolean" -> Type.BOOLEAN_TYPE;
            case "java/lang/Character" -> Type.CHAR_TYPE;
            case "java/lang/Byte" -> Type.BYTE_TYPE;
            case "java/lang/Short" -> Type.SHORT_TYPE;
            case "java/lang/Float" -> Type.FLOAT_TYPE;
            case "java/lang/Double" -> Type.DOUBLE_TYPE;
            default -> throw new IllegalStateException("cannot unbox " + boxClass);
        };
    }

    static Object box(VM vm, Object v, Type t) {
        String cls = switch (t.getSort()) {
            case Type.INT -> "java/lang/Integer";
            case Type.LONG -> "java/lang/Long";
            case Type.BOOLEAN -> "java/lang/Boolean";
            case Type.CHAR -> "java/lang/Character";
            case Type.BYTE -> "java/lang/Byte";
            case Type.SHORT -> "java/lang/Short";
            case Type.FLOAT -> "java/lang/Float";
            default -> "java/lang/Double";
        };
        return vm.callStatic(cls, "valueOf(" + t.getDescriptor() + ")L" + cls + ";", v);
    }
}
