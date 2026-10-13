package org.isolatte.guest;

import org.teavm.platform.metadata.StringResource;

final class StrRes implements StringResource {
    private final String value;

    StrRes(String value) {
        this.value = value;
    }

    @Override
    public String getValue() {
        return value;
    }
}
