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
    // Permissive WireGuard userspace engine (Apache-2.0 lib wrapping MIT wireguard-go).
    // This is the only third-party piece; everything else here is from scratch.
    implementation("com.wireguard.android:tunnel:1.0.20230706")
}
