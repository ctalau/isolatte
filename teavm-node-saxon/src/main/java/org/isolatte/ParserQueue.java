package org.isolatte;

/** Saxon's parser pool runs on one Node thread in this experiment. */
public final class ParserQueue<E> extends java.util.ArrayDeque<E> {
    public ParserQueue() { super(); }
    public ParserQueue(java.util.Collection<? extends E> values) { super(values); }
}
