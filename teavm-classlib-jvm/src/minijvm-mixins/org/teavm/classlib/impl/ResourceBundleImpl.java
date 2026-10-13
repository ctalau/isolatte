package org.teavm.classlib.impl;

import java.util.Map;
import java.util.ResourceBundle;
import java.util.function.Supplier;
import jdk.internal.mixin.MixinReplace;

/**
 * Mixin: TeaVM builds the bundle table at compile time (metaprogramming, from
 * META-INF/services/java.util.ResourceBundle). Here it is a lazy guest map.
 */
public class ResourceBundleImpl {
    @MixinReplace
    public static Map<String, Supplier<ResourceBundle>> createBundleMap(boolean b) {
        return new org.isolatte.guest.BundleMap();
    }
}
