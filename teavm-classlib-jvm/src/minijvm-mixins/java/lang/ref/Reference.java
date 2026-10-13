package java.lang.ref;

/** Mixin: fields and callback miniJVM's collector expects (weak semantics are not provided). */
public abstract class Reference<T> {
    private Object target;

    static void vmEnqueneReference(Reference<?> ref) {
    }
}
