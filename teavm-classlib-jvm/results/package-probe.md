| TeaVM package (raw, alone) | HotSpot result |
| --- | --- |
| `java/**` | Incompatible definition of java.lang.Object |
| `java/lang/` | Incompatible definition of java.lang.Object |
| `java/lang/annotation/` | java/lang/ClassCircularityError: java/lang/annotation/Annotation |
| `java/lang/invoke/` | Invalid layout of well-known class: use -Xlog:class+load=info to see the origin of the problem class |
| `java/lang/ref/` | Invalid layout of well-known class: java.lang.ref.Reference |
| `java/lang/reflect/` | Invalid layout of well-known class: java.lang.reflect.AccessibleObject |
| `java/io/` | java.lang.NoSuchMethodError: 'void java.io.FileInputStream.<init>(java.io.FileDescriptor)' |
| `java/math/` | boots, hello-world OK |
| `java/net/` | java.lang.NullPointerException: Cannot invoke "jdk.internal.access.JavaNetUriAccess.create(String, String)" because "jdk.internal.module.SystemModuleF |
| `java/net/impl/` | boots, hello-world OK |
| `java/nio/` | java.lang.NoClassDefFoundError: org/teavm/classlib/PlatformDetector |
| `java/nio/channels/` | boots, hello-world OK |
| `java/nio/charset/**` | java.lang.InternalError: platform encoding not initialized |
| `java/nio/file/**` | A non-java.base package was loaded prior to module system initialization: java/nio/file/impl |
| `java/security/` | Invalid layout of well-known class: use -Xlog:class+load=info to see the origin of the problem class |
| `java/text/` | boots, hello-world OK |
| `java/util/` | java.lang.ExceptionInInitializerError |
| `java/util/concurrent/**` | java.lang.BootstrapMethodError: bootstrap method initialization exception |
| `java/util/function/` | boots, hello-world OK |
| `java/util/jar/` | boots, hello-world OK |
| `java/util/logging/` | java.lang.LayerInstantiationException: Package java.util.logging in both module java.logging and module java.base |
| `java/util/random/` | boots, hello-world OK |
| `java/util/regex/` | boots, hello-world OK |
| `java/util/stream/**` | java.lang.NoClassDefFoundError: java/util/TemplateCollections$ImmutableArrayList |
| `java/util/zip/` | boots, hello-world OK |
| `java/awt/` | java.lang.LayerInstantiationException: Package java.awt in both module java.base and module java.desktop |
