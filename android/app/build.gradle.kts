plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.rpndirect.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.rpndirect.app"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "0.1-phase1"
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Our own shared ICE + userspace-WireGuard engine, built from core/ via
    // `gomobile bind` into app/libs/rpncore.aar by the CI workflow. Embeds
    // wireguard-go + pion/ice. No third-party Android WireGuard library.
    implementation(files("libs/rpncore.aar"))
}
