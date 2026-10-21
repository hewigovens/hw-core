plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

// Published coordinates follow the Rust workspace version unless -PhwcoreVersion overrides it.
val hwcoreVersion: String = providers.gradleProperty("hwcoreVersion").orNull
    ?: Regex("""(?m)^version\s*=\s*"([^"]+)"""")
        .find(rootDir.resolve("../Cargo.toml").readText())
        ?.groupValues?.get(1)
    ?: error("workspace version not found in Cargo.toml")

android {
    namespace = "dev.hewig.hwcore.lib"
    compileSdk = 35

    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "dev.hewig.hwcore"
            artifactId = "hwcore"
            version = hwcoreVersion
            afterEvaluate { from(components["release"]) }
        }
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.15.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("androidx.core:core-ktx:1.15.0")
    testImplementation("junit:junit:4.13.2")
}
