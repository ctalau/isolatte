package org.isolatte.guest;

import java.util.ArrayList;
import java.util.List;
import org.teavm.platform.metadata.Resource;
import org.teavm.platform.metadata.ResourceArray;

@SuppressWarnings("rawtypes")
final class ArrRes implements ResourceArray {
    private final List<Object> list = new ArrayList<>();

    void addValue(Object value) {
        list.add(value);
    }

    @Override
    public int size() {
        return list.size();
    }

    @Override
    public Resource get(int i) {
        return (Resource) list.get(i);
    }

    @Override
    public void add(Resource elem) {
        list.add(elem);
    }
}
