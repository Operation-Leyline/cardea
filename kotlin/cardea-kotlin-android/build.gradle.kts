import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
}

description = "The Android parts of Cardea: Custom Tabs sign-in, Keystore storage and Google proofs."

android {
    namespace = "com.operationleyline.cardea.android"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

kotlin {
    explicitApi()
    compilerOptions.jvmTarget.set(JvmTarget.JVM_11)
}

dependencies {
    api(project(":cardea-kotlin-core"))
    // CardeaBrowserContract is an ActivityResultContract, so apps see this one.
    api(libs.androidx.activity)
    implementation(libs.androidx.credentials)
    implementation(libs.coroutines.android)
    implementation(libs.androidx.browser)
    implementation(libs.googleid)
    // Credential Manager on Android 13 and older goes through Google Play services.
    runtimeOnly(libs.androidx.credentials.play)
    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
            }
        }
    }
}
