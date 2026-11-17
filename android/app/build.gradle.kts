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
        versionCode = 2
        versionName = "2.0"
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
    androidResources { noCompress += listOf("task", "tflite") }
    packaging { resources { excludes += listOf("META-INF/*.version", "META-INF/LICENSE*", "META-INF/NOTICE*", "META-INF/DEPENDENCIES", "META-INF/*.kotlin_module", "META-INF/versions/**") } }
}

dependencies {
    implementation("org.opencv:opencv:4.12.0")
    implementation("androidx.work:work-runtime:2.10.5")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.exifinterface:exifinterface:1.4.1")
    implementation("com.google.mediapipe:tasks-vision:0.10.29")
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    implementation("com.anthropic:anthropic-java:3.8.0")
    implementation("com.google.mlkit:text-recognition-korean:16.0.1")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    implementation("com.google.zxing:core:3.5.3")
    testImplementation("junit:junit:4.13.2")
    // 컴퓨터(JVM)에서 이미지 분석 코드를 시험하기 위한 OpenCV (리눅스·윈도·맥 네이티브 포함)
    testImplementation("org.openpnp:opencv:4.9.0-0")
    testImplementation("org.json:json:20240303")
}

// 단위 시험에서는 안드로이드용 OpenCV 대신 컴퓨터용 OpenCV 를 씁니다 (같은 org.opencv API)
configurations.configureEach {
    if (name.endsWith("UnitTestRuntimeClasspath")) exclude(group = "org.opencv", module = "opencv")
}
