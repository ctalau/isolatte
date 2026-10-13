package org.isolatte.vm;

/**
 * A guest object. {@code fields} holds the instance fields (slots assigned by {@link VClass});
 * {@code hidden} is VM-private state the class library reaches only through natives, e.g. the host
 * {@code String} behind a guest {@code java.lang.String} (TeaVM's TString has no character field: its
 * storage is entirely backend-provided) or the {@link VClass} behind a {@code ClassInfo}.
 */
class VObject {
    final VClass cls;
    final Object[] fields;
    Object hidden;

    VObject(VClass cls) {
        this.cls = cls;
        this.fields = new Object[cls.instanceSlots];
        cls.fillDefaults(fields);
    }

    @Override
    public String toString() {
        return cls.name + "@" + Integer.toHexString(System.identityHashCode(this));
    }
}
