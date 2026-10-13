package org.isolatte.vm;

/**
 * A host implementation of a guest method. {@code args} are in JVM order (receiver first for
 * instance methods); int-like values (boolean, byte, char, short, int) are Integers, as on the
 * operand stack. Returns the result the same way, or null for void.
 */
@FunctionalInterface
interface Native {
    Object call(Object[] args);
}
