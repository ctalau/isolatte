package org.isolatte.minijvm;

import static org.objectweb.asm.Opcodes.*;

import java.util.ArrayList;
import java.util.List;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Removes invokedynamic, as TeaVM's compiler does: TeaVM's {@code LambdaMetafactory} and
 * {@code StringConcatFactory} are compiler intrinsics, not runnable code, while miniJVM runs the
 * bootstrap method as Java. Lambdas and method references become ordinary classes; string
 * concatenation becomes a synthetic static method built on (TeaVM's) StringBuilder.
 */
final class IndyDesugar {
    private final List<ClassNode> generated = new ArrayList<>();
    private int counter;

    /** Rewrites {@code cls} in place; returns the lambda classes it needed. */
    List<ClassNode> desugar(ClassNode cls) {
        generated.clear();
        List<MethodNode> added = new ArrayList<>();
        for (MethodNode m : cls.methods) {
            if (m.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn : m.instructions.toArray()) {
                if (insn instanceof InvokeDynamicInsnNode indy) {
                    String bsm = indy.bsm.getOwner() + "." + indy.bsm.getName();
                    AbstractInsnNode replacement = switch (bsm) {
                        case "java/lang/invoke/LambdaMetafactory.metafactory",
                             "java/lang/invoke/LambdaMetafactory.altMetafactory" -> lambda(cls, indy);
                        case "java/lang/invoke/StringConcatFactory.makeConcatWithConstants" ->
                                concat(cls, indy, (String) indy.bsmArgs[0], added);
                        case "java/lang/invoke/StringConcatFactory.makeConcat" ->
                                concat(cls, indy, "\u0001".repeat(Type.getArgumentTypes(indy.desc).length), added);
                        default -> throw new IllegalStateException(cls.name + ": unsupported bootstrap " + bsm);
                    };
                    m.instructions.set(indy, replacement);
                }
            }
        }
        cls.methods.addAll(added);
        return new ArrayList<>(generated);
    }

    // ------------------------------------------------------------------ string concatenation

    private AbstractInsnNode concat(ClassNode cls, InvokeDynamicInsnNode indy, String recipe, List<MethodNode> added) {
        String name = "concat$" + (counter++);
        Type[] args = Type.getArgumentTypes(indy.desc);
        MethodNode m = new MethodNode(ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC, name, indy.desc, null, null);
        InsnList c = m.instructions;
        String sb = "java/lang/StringBuilder";
        c.add(new TypeInsnNode(NEW, sb));
        c.add(new InsnNode(DUP));
        c.add(new MethodInsnNode(INVOKESPECIAL, sb, "<init>", "()V", false));
        int arg = 0;
        int slot = 0;
        int cst = 1;
        StringBuilder literal = new StringBuilder();
        for (int i = 0; i <= recipe.length(); i++) {
            char ch = i < recipe.length() ? recipe.charAt(i) : '\u0001';
            boolean end = i == recipe.length();
            if ((ch == '\u0001' || ch == '\u0002' || end) && literal.length() > 0) {
                c.add(new LdcInsnNode(literal.toString()));
                c.add(new MethodInsnNode(INVOKEVIRTUAL, sb, "append", "(Ljava/lang/String;)L" + sb + ";", false));
                literal.setLength(0);
            }
            if (end) {
                break;
            }
            if (ch == '\u0001') {
                Type t = args[arg++];
                c.add(new VarInsnNode(t.getOpcode(ILOAD), slot));
                slot += t.getSize();
                String desc = switch (t.getSort()) {
                    case Type.BOOLEAN -> "Z";
                    case Type.CHAR -> "C";
                    case Type.BYTE, Type.SHORT, Type.INT -> "I";
                    case Type.LONG -> "J";
                    case Type.FLOAT -> "F";
                    case Type.DOUBLE -> "D";
                    default -> t.getDescriptor().equals("Ljava/lang/String;") ? "Ljava/lang/String;" : "Ljava/lang/Object;";
                };
                c.add(new MethodInsnNode(INVOKEVIRTUAL, sb, "append", "(" + desc + ")L" + sb + ";", false));
            } else if (ch == '\u0002') {
                c.add(new LdcInsnNode(String.valueOf(indy.bsmArgs[cst++])));
                c.add(new MethodInsnNode(INVOKEVIRTUAL, sb, "append", "(Ljava/lang/String;)L" + sb + ";", false));
            } else {
                literal.append(ch);
            }
        }
        c.add(new MethodInsnNode(INVOKEVIRTUAL, sb, "toString", "()Ljava/lang/String;", false));
        c.add(new InsnNode(ARETURN));
        added.add(m);
        return new MethodInsnNode(INVOKESTATIC, cls.name, name, indy.desc, false);
    }

    // ------------------------------------------------------------------ lambdas

    private AbstractInsnNode lambda(ClassNode host, InvokeDynamicInsnNode indy) {
        Object[] a = indy.bsmArgs;
        Type samType = (Type) a[0];
        Handle impl = (Handle) a[1];
        Type indyType = Type.getMethodType(indy.desc);
        Type[] captured = indyType.getArgumentTypes();
        List<String> ifaces = new ArrayList<>();
        ifaces.add(indyType.getReturnType().getInternalName());
        List<Type> descs = new ArrayList<>();
        descs.add(samType);
        if (indy.bsm.getName().equals("altMetafactory")) {
            int flags = (Integer) a[3];
            int i = 4;
            if ((flags & 2) != 0) { // FLAG_MARKERS
                int n = (Integer) a[i++];
                for (int k = 0; k < n; k++) {
                    ifaces.add(((Type) a[i++]).getInternalName());
                }
            }
            if ((flags & 4) != 0) { // FLAG_BRIDGES
                int n = (Integer) a[i++];
                for (int k = 0; k < n; k++) {
                    descs.add((Type) a[i++]);
                }
            }
        }
        ClassNode lc = new ClassNode();
        lc.version = V1_6;
        lc.access = ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC | ACC_SUPER;
        lc.name = host.name + "$$Lambda$" + (counter++);
        lc.superName = "java/lang/Object";
        lc.interfaces = ifaces;
        lc.sourceFile = host.sourceFile;
        for (int i = 0; i < captured.length; i++) {
            lc.fields.add(new FieldNode(ACC_PRIVATE | ACC_FINAL, "c" + i, captured[i].getDescriptor(), null, null));
        }
        String ctorDesc = Type.getMethodDescriptor(Type.VOID_TYPE, captured);
        MethodNode ctor = new MethodNode(ACC_PRIVATE, "<init>", ctorDesc, null, null);
        ctor.instructions.add(new VarInsnNode(ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        int slot = 1;
        for (int i = 0; i < captured.length; i++) {
            ctor.instructions.add(new VarInsnNode(ALOAD, 0));
            ctor.instructions.add(new VarInsnNode(captured[i].getOpcode(ILOAD), slot));
            ctor.instructions.add(new FieldInsnNode(PUTFIELD, lc.name, "c" + i, captured[i].getDescriptor()));
            slot += captured[i].getSize();
        }
        ctor.instructions.add(new InsnNode(RETURN));
        lc.methods.add(ctor);

        MethodNode factory = new MethodNode(ACC_PUBLIC | ACC_STATIC, "create", indy.desc, null, null);
        factory.instructions.add(new TypeInsnNode(NEW, lc.name));
        factory.instructions.add(new InsnNode(DUP));
        slot = 0;
        for (Type t : captured) {
            factory.instructions.add(new VarInsnNode(t.getOpcode(ILOAD), slot));
            slot += t.getSize();
        }
        factory.instructions.add(new MethodInsnNode(INVOKESPECIAL, lc.name, "<init>", ctorDesc, false));
        factory.instructions.add(new InsnNode(ARETURN));
        lc.methods.add(factory);

        List<String> done = new ArrayList<>();
        for (Type d : descs) {
            if (!done.contains(d.getDescriptor())) {
                done.add(d.getDescriptor());
                lc.methods.add(samMethod(lc, indy.name, d, captured, impl));
            }
        }
        generated.add(lc);
        return new MethodInsnNode(INVOKESTATIC, lc.name, "create", indy.desc, false);
    }

    private static MethodNode samMethod(ClassNode lc, String name, Type sam, Type[] captured, Handle impl) {
        MethodNode m = new MethodNode(ACC_PUBLIC, name, sam.getDescriptor(), null, null);
        InsnList c = m.instructions;
        int tag = impl.getTag();
        Type[] implArgs = Type.getArgumentTypes(impl.getDesc());
        List<Type> targets = new ArrayList<>();
        if (tag == H_INVOKEVIRTUAL || tag == H_INVOKEINTERFACE || tag == H_INVOKESPECIAL) {
            targets.add(Type.getObjectType(impl.getOwner()));
        }
        targets.addAll(List.of(implArgs));
        if (tag == H_NEWINVOKESPECIAL) {
            c.add(new TypeInsnNode(NEW, impl.getOwner()));
            c.add(new InsnNode(DUP));
        }
        int t = 0;
        for (int i = 0; i < captured.length; i++, t++) {
            c.add(new VarInsnNode(ALOAD, 0));
            c.add(new FieldInsnNode(GETFIELD, lc.name, "c" + i, captured[i].getDescriptor()));
            adapt(c, captured[i], targets.get(t));
        }
        int slot = 1;
        for (Type arg : sam.getArgumentTypes()) {
            c.add(new VarInsnNode(arg.getOpcode(ILOAD), slot));
            slot += arg.getSize();
            adapt(c, arg, targets.get(t++));
        }
        switch (tag) {
            case H_INVOKESTATIC -> c.add(new MethodInsnNode(INVOKESTATIC, impl.getOwner(), impl.getName(), impl.getDesc(), impl.isInterface()));
            case H_INVOKEVIRTUAL -> c.add(new MethodInsnNode(INVOKEVIRTUAL, impl.getOwner(), impl.getName(), impl.getDesc(), false));
            case H_INVOKEINTERFACE -> c.add(new MethodInsnNode(INVOKEINTERFACE, impl.getOwner(), impl.getName(), impl.getDesc(), true));
            case H_INVOKESPECIAL, H_NEWINVOKESPECIAL ->
                    c.add(new MethodInsnNode(INVOKESPECIAL, impl.getOwner(), impl.getName(), impl.getDesc(), impl.isInterface()));
            default -> throw new IllegalStateException("method handle kind " + tag);
        }
        Type ret = tag == H_NEWINVOKESPECIAL ? Type.getObjectType(impl.getOwner()) : Type.getReturnType(impl.getDesc());
        Type samRet = sam.getReturnType();
        if (samRet.getSort() == Type.VOID) {
            if (ret.getSize() > 0) {
                c.add(new InsnNode(ret.getSize() == 2 ? POP2 : POP));
            }
        } else {
            adapt(c, ret, samRet);
        }
        c.add(new InsnNode(samRet.getOpcode(IRETURN)));
        return m;
    }

    private static boolean primitive(Type t) {
        return t.getSort() < Type.ARRAY;
    }

    /** Converts the value on the stack from {@code from} to {@code to}: cast, box, unbox or widen. */
    private static void adapt(InsnList c, Type from, Type to) {
        if (from.equals(to)) {
            return;
        }
        boolean fp = primitive(from);
        boolean tp = primitive(to);
        if (!fp && !tp) {
            if (!to.getDescriptor().equals("Ljava/lang/Object;")) {
                c.add(new TypeInsnNode(CHECKCAST, to.getSort() == Type.ARRAY ? to.getDescriptor() : to.getInternalName()));
            }
        } else if (fp && !tp) {
            String box = boxOf(from);
            c.add(new MethodInsnNode(INVOKESTATIC, box, "valueOf", "(" + from.getDescriptor() + ")L" + box + ";", false));
        } else if (!fp) {
            String box = from.getDescriptor().equals("Ljava/lang/Object;") || from.getDescriptor().equals("Ljava/lang/Number;")
                    ? boxOf(to) : from.getInternalName();
            Type unboxed = unboxed(box);
            if (unboxed == null) { // e.g. Number -> int
                box = "java/lang/Number";
                unboxed = to;
            }
            c.add(new TypeInsnNode(CHECKCAST, box));
            c.add(new MethodInsnNode(INVOKEVIRTUAL, box, unboxed.getClassName() + "Value", "()" + unboxed.getDescriptor(), false));
            widen(c, unboxed, to);
        } else {
            widen(c, from, to);
        }
    }

    private static void widen(InsnList c, Type from, Type to) {
        int f = from.getSort();
        int t = to.getSort();
        if (f == t) {
            return;
        }
        boolean intLike = f <= Type.INT;
        if (intLike && t == Type.LONG) c.add(new InsnNode(I2L));
        else if (intLike && t == Type.FLOAT) c.add(new InsnNode(I2F));
        else if (intLike && t == Type.DOUBLE) c.add(new InsnNode(I2D));
        else if (f == Type.LONG && t == Type.FLOAT) c.add(new InsnNode(L2F));
        else if (f == Type.LONG && t == Type.DOUBLE) c.add(new InsnNode(L2D));
        else if (f == Type.FLOAT && t == Type.DOUBLE) c.add(new InsnNode(F2D));
    }

    static String boxOf(Type t) {
        return switch (t.getSort()) {
            case Type.BOOLEAN -> "java/lang/Boolean";
            case Type.CHAR -> "java/lang/Character";
            case Type.BYTE -> "java/lang/Byte";
            case Type.SHORT -> "java/lang/Short";
            case Type.INT -> "java/lang/Integer";
            case Type.LONG -> "java/lang/Long";
            case Type.FLOAT -> "java/lang/Float";
            default -> "java/lang/Double";
        };
    }

    private static Type unboxed(String box) {
        return switch (box) {
            case "java/lang/Boolean" -> Type.BOOLEAN_TYPE;
            case "java/lang/Character" -> Type.CHAR_TYPE;
            case "java/lang/Byte" -> Type.BYTE_TYPE;
            case "java/lang/Short" -> Type.SHORT_TYPE;
            case "java/lang/Integer" -> Type.INT_TYPE;
            case "java/lang/Long" -> Type.LONG_TYPE;
            case "java/lang/Float" -> Type.FLOAT_TYPE;
            case "java/lang/Double" -> Type.DOUBLE_TYPE;
            default -> null;
        };
    }
}
