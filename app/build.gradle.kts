import org.gradle.internal.os.OperatingSystem

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

/**
 * Builds the Rust engine (the `replay` executable) for one Android ABI with Cargo, linking with
 * the LLVM toolchain of the NDK. The executable is packaged as `libreplay.so` so that the
 * package installer extracts it into the native library directory, the one place from which an
 * application may execute its own files.
 */
abstract class CargoBuild : DefaultTask() {
    @get:Input abstract val cargo: Property<String>
    @get:Input abstract val abi: Property<String>
    @get:Input abstract val target: Property<String>
    @get:Input abstract val linker: Property<String>
    @get:Internal abstract val workspace: DirectoryProperty
    @get:InputFiles abstract val sources: ConfigurableFileCollection
    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty

    @get:Inject abstract val execOperations: ExecOperations

    @TaskAction
    fun build() {
        val triple = target.get()
        val variable = "CARGO_TARGET_" + triple.uppercase().replace('-', '_') + "_LINKER"
        execOperations.exec {
            workingDir = workspace.get().asFile
            environment(variable, linker.get())
            commandLine(cargo.get(), "build", "--release", "--locked", "-p", "replay", "--target", triple)
        }
        val executable = workspace.get().file("target/$triple/release/replay").asFile
        val directory = outputDirectory.get().dir(abi.get()).asFile
        directory.mkdirs()
        executable.copyTo(directory.resolve("libreplay.so"), overwrite = true)
    }
}

android {
    namespace = "dev.nercone.replayintegrity"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "dev.nercone.replayintegrity"
        minSdk = 33
        targetSdk = 37
        versionCode = 200
        versionName = "0.2.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        compose = true
        aidl = true
    }

    packaging {
        jniLibs {
            // The engine must exist as a file to be executed.
            useLegacyPackaging = true
        }
    }
}

val abis = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "armeabi-v7a" to "armv7-linux-androideabi",
    "x86_64" to "x86_64-linux-android",
)
val clangPrefix = mapOf(
    "aarch64-linux-android" to "aarch64-linux-android",
    "armv7-linux-androideabi" to "armv7a-linux-androideabi",
    "x86_64-linux-android" to "x86_64-linux-android",
)
val hostTag = when {
    OperatingSystem.current().isMacOsX -> "darwin-x86_64"
    OperatingSystem.current().isWindows -> "windows-x86_64"
    else -> "linux-x86_64"
}
val workspaceDirectory = rootProject.layout.projectDirectory
val minimumSdk = 33
// Cargo from the CARGO variable, the rustup default location, or the PATH, in that order.
val cargoExecutable = providers.environmentVariable("CARGO").orElse(
    providers.systemProperty("user.home").map { home ->
        val candidate = File(home, ".cargo/bin/cargo" + if (OperatingSystem.current().isWindows) ".exe" else "")
        if (candidate.canExecute()) candidate.absolutePath else "cargo"
    },
)

val cargoTasks = abis.map { (abi, triple) ->
    tasks.register<CargoBuild>("cargoBuild-$abi") {
        cargo.set(cargoExecutable)
        this.abi.set(abi)
        target.set(triple)
        linker.set(androidComponents.sdkComponents.ndkDirectory.map { ndk ->
            val suffix = if (OperatingSystem.current().isWindows) ".cmd" else ""
            ndk.file("toolchains/llvm/prebuilt/$hostTag/bin/${clangPrefix.getValue(triple)}$minimumSdk-clang$suffix").asFile.absolutePath
        })
        workspace.set(workspaceDirectory)
        sources.from(workspaceDirectory.dir("crates"), workspaceDirectory.file("Cargo.toml"), workspaceDirectory.file("Cargo.lock"))
        outputDirectory.set(layout.buildDirectory.dir("rust/$abi"))
    }
}

androidComponents {
    onVariants { variant ->
        cargoTasks.forEach { task -> variant.sources.jniLibs?.addGeneratedSourceDirectory(task, CargoBuild::outputDirectory) }
    }
}

dependencies {
    implementation(libs.androidx.core)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.work)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.shizuku.api)
    implementation(libs.shizuku.provider)
    testImplementation(libs.junit)
}
