package org.isolatte.guest;

import java.util.Map;

/** Base of the builder-generated classes for TeaVM's object resources (getters call get). */
public abstract class ObjRes {
    private final Map<String, Object> fields;

    protected ObjRes(Map<String, Object> fields) {
        this.fields = fields;
    }

    protected final Object get(String name) {
        return fields.get(name);
    }
}
