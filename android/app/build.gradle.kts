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
    testOptions { unitTests { isIncludeAndroidResources = true } }
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
    // 화면(UI)을 컴퓨터에서 이미지로 그려 눈으로 확인하는 시험용 (Robolectric 네이티브 그래픽)
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
}

// 단위 시험에서는 안드로이드용 OpenCV 대신 컴퓨터용 OpenCV 를 씁니다 (같은 org.opencv API)
configurations.configureEach {
    if (name.endsWith("UnitTestRuntimeClasspath")) exclude(group = "org.opencv", module = "opencv")
}

// 스크린샷 시험은 -PuiShots=/저장/폴더 로 켭니다 (없으면 건너뜀). 안드로이드 SDK 파일을 미리 받아 둔 폴더는 -ProbolectricDir=... 로 지정 (없으면 Robolectric 이 알아서 내려받음)
tasks.withType<Test>().configureEach {
    (project.findProperty("uiShots") as String?)?.let { systemProperty("ui.shots.dir", it) }
    (project.findProperty("uiTag") as String?)?.let { systemProperty("ui.shots.tag", it) }
    (project.findProperty("robolectricDir") as String?)?.let {
        systemProperty("robolectric.offline", "true"); systemProperty("robolectric.dependency.dir", it)
    }
    maxHeapSize = "3g"
}
