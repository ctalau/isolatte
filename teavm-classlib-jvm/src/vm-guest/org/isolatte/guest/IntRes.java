package org.isolatte.guest;

import org.teavm.platform.metadata.IntResource;

final class IntRes implements IntResource {
    private final int value;

    IntRes(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }
}
