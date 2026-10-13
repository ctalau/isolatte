package org.isolatte.vm;

/** A guest array of references. Guest primitive arrays are plain host arrays (int[], char[], ...). */
final class RefArray {
    final VClass cls;
    final Object[] data;

    RefArray(VClass cls, int length) {
        this.cls = cls;
        this.data = new Object[length];
    }

    RefArray(VClass cls, Object[] data) {
        this.cls = cls;
        this.data = data;
    }
}
