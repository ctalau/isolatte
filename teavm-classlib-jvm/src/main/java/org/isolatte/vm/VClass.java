package org.isolatte.vm;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

/** A guest class, array class or primitive type. */
final class VClass {
    static final int LOADED = 0;
    static final int INITIALIZING = 1;
    static final int INITIALIZED = 2;

    final String name;
    final ClassNode node;
    final int access;
    VClass superClass;
    VClass[] interfaces = new VClass[0];
    /** Arrays: the component type. */
    final VClass component;
    /** Primitive types: the descriptor character (I, J, ..., V). */
    final char primitive;

    final Map<String, VField> fields = new LinkedHashMap<>();
    final Map<String, VMethod> methods = new LinkedHashMap<>();
    final Map<String, VMethod> virtualCache = new HashMap<>();
    private final Map<VClass, Boolean> assignableCache = new HashMap<>();
    int instanceSlots;
    Object[] instanceDefaults = new Object[0];
    Object[] statics = new Object[0];
    int state = LOADED;
    VClass arrayClass;
    VObject classInfo;
    VObject classObject;
    String sourceFile;

    VClass(String name, ClassNode node, int access, VClass component, char primitive) {
        this.name = name;
        this.node = node;
        this.access = access;
        this.component = component;
        this.primitive = primitive;
        this.sourceFile = node != null ? node.sourceFile : null;
    }

    boolean isInterface() {
        return (access & Opcodes.ACC_INTERFACE) != 0;
    }

    boolean isArray() {
        return component != null;
    }

    boolean isPrimitive() {
        return primitive != 0;
    }

    void fillDefaults(Object[] slots) {
        System.arraycopy(instanceDefaults, 0, slots, 0, instanceDefaults.length);
    }

    /** The guest's {@code Class.getName()}: dots, and descriptors for arrays. */
    String javaName() {
        if (isPrimitive()) {
            switch (primitive) {
                case 'Z': return "boolean";
                case 'B': return "byte";
                case 'C': return "char";
                case 'S': return "short";
                case 'I': return "int";
                case 'J': return "long";
                case 'F': return "float";
                case 'D': return "double";
                default: return "void";
            }
        }
        return name.replace('/', '.');
    }

    /** The descriptor of this type, e.g. {@code I}, {@code Ljava/lang/String;}, {@code [I}. */
    String descriptor() {
        if (isPrimitive()) {
            return String.valueOf(primitive);
        }
        return isArray() ? name : "L" + name + ";";
    }

    boolean isAssignableTo(VClass target) {
        if (target == this) {
            return true;
        }
        Boolean cached = assignableCache.get(target);
        if (cached == null) {
            cached = computeAssignable(target);
            assignableCache.put(target, cached);
        }
        return cached;
    }

    private boolean computeAssignable(VClass target) {
        if (isPrimitive() || target.isPrimitive()) {
            return false;
        }
        if (target.superClass == null && !target.isInterface() && !target.isArray()) {
            return true; // java.lang.Object
        }
        if (isArray()) {
            if (target.isArray()) {
                if (component.isPrimitive() || target.component.isPrimitive()) {
                    return component == target.component;
                }
                return component.isAssignableTo(target.component);
            }
            return target.name.equals("java/lang/Cloneable") || target.name.equals("java/io/Serializable");
        }
        for (VClass c = this; c != null; c = c.superClass) {
            if (c == target) {
                return true;
            }
            if (target.isInterface()) {
                for (VClass i : c.interfaces) {
                    if (i.isAssignableTo(target)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return name;
    }
}
