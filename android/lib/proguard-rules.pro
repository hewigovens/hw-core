# Keep uniffi generated classes
-keep class uniffi.hw_ffi.** { *; }

# Keep JNA classes
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
