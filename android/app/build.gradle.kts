import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// 支持的目标 ABI：产物名与 ndk.abiFilters 的唯一来源
val miaospeedAbiFilters = listOf("arm64-v8a")

// miaospeed 核心版本：取自仓库 git tag，与 Go 二进制构建时注入的 -X main.VERSION 一致
fun coreVersion(): String = runCatching {
    val repoRoot = rootProject.projectDir.parentFile
    val p = ProcessBuilder("git", "-C", repoRoot.absolutePath, "describe", "--tags", "--abbrev=0")
        .redirectErrorStream(true)
        .start()
    p.inputStream.bufferedReader().readText()
        .takeWhile { !it.isWhitespace() }
        .also { p.waitFor() }
        .takeIf { it.firstOrNull()?.isDigit() == true }
        ?: "unknown"
}.getOrDefault("unknown")

android {
    namespace = "com.miaospeed.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.miaospeed.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "1.0.0"
        ndk {
            abiFilters.addAll(miaospeedAbiFilters)
        }
        buildConfigField("String", "CORE_VERSION", "\"${coreVersion()}\"")
    }

    // 签名信息在 android/keystore.properties（不入库）；缺失时回退 debug 签名
    val ksPropsFile = rootProject.file("keystore.properties")
    val ksExists = ksPropsFile.exists()

    signingConfigs {
        if (ksExists) {
            val props = Properties().apply { ksPropsFile.inputStream().use { load(it) } }
            create("release") {
                storeFile = rootProject.file(props.getProperty("storeFile"))
                storePassword = props.getProperty("storePassword")
                keyAlias = props.getProperty("keyAlias")
                keyPassword = props.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (ksExists) signingConfigs.getByName("release") else signingConfigs.getByName("debug")
        }
    }

    // 产物名：miaospeed-<核心版本>-<abi>.apk
    applicationVariants.all {
        if (name == "release") {
            outputs.all {
                (this as com.android.build.gradle.internal.api.BaseVariantOutputImpl).outputFileName =
                    "miaospeed-${coreVersion()}-${miaospeedAbiFilters.joinToString("-")}.apk"
            }
        }
    }

    // 关键：让 libmiaospeed.so 安装后解压到 nativeLibraryDir，从而可执行
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
