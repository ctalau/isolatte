package org.isolatte.vm;

/** A resolved field: an instance slot, or a static slot of its declaring class. */
final class VField {
    final VClass owner;
    final String name;
    final String desc;
    final boolean isStatic;
    final int slot;
    final int access;

    VField(VClass owner, String name, String desc, int access, int slot) {
        this.owner = owner;
        this.name = name;
        this.desc = desc;
        this.access = access;
        this.isStatic = (access & org.objectweb.asm.Opcodes.ACC_STATIC) != 0;
        this.slot = slot;
    }

    static Object defaultValue(String desc) {
        switch (desc.charAt(0)) {
            case 'J':
                return 0L;
            case 'F':
                return 0f;
            case 'D':
                return 0d;
            case 'L':
            case '[':
                return null;
            default:
                return 0;
        }
    }
}
