plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.selfcheck.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.selfcheck.app"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
        // 대부분의 휴대폰(arm64)만 포함해서 APK 크기를 줄입니다
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
    packaging { jniLibs { useLegacyPackaging = false } }
    androidResources { noCompress += "task" }
}

dependencies {
    implementation("org.opencv:opencv:4.12.0")
    implementation("androidx.work:work-runtime:2.10.5")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.exifinterface:exifinterface:1.4.1")
    implementation("com.google.mediapipe:tasks-vision:0.10.29")
}
