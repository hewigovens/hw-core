# Applied to apps that depend on this library when they minify.

# Keep uniffi generated classes
-keep class uniffi.hwcore.** { *; }

# Keep JNA classes
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }

# Keep btleplug's droidplug Java classes; Rust looks them up by name and registers native methods on them
-keep class com.nonpolynomial.btleplug.** { *; }
-keep class io.github.gedgygedgy.rust.** { *; }
