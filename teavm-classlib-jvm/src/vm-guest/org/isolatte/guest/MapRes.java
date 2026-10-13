package org.isolatte.guest;

import java.util.LinkedHashMap;
import java.util.Map;
import org.teavm.platform.metadata.Resource;
import org.teavm.platform.metadata.ResourceMap;

@SuppressWarnings({"rawtypes", "unchecked"})
final class MapRes implements ResourceMap {
    private final Map<String, Object> map = new LinkedHashMap<>();

    void put(String key, Object value) {
        map.put(key, value);
    }

    @Override
    public boolean has(String key) {
        return map.containsKey(key);
    }

    @Override
    public Resource get(String key) {
        return (Resource) map.get(key);
    }

    @Override
    public String[] keys() {
        return map.keySet().toArray(new String[0]);
    }
}
