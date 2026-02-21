# Keep uniffi generated classes
-keep class uniffi.hwcore.** { *; }

# Keep JNA classes
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
