package dev.nercone.replayintegrity.engine

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The data types the engine (`libreplay.so`) prints as JSON. They mirror the Rust reports in
 * `crates/replay`; fields the user interface does not use are left out, and unknown fields are
 * ignored, so the application and the engine can be updated apart.
 */

@Serializable
data class LogLine(val time: Long, val level: String, val message: String)

/** The one JSON object every engine command prints. */
@Serializable
data class EngineResponse(
    val ok: Boolean = false,
    val result: JsonElement? = null,
    val error: EngineError? = null,
    val log: List<LogLine> = emptyList(),
)

@Serializable
data class EngineError(val kind: String, val message: String)

/** A root manager: the names match the Rust `RootManager` (camelCase). */
@Serializable
enum class RootManager {
    @SerialName("magisk") MAGISK,
    @SerialName("kernelSU") KERNEL_SU,
    @SerialName("aPatch") APATCH,
}

@Serializable
enum class Component {
    @SerialName("keystore") KEYSTORE,
    @SerialName("integrity") INTEGRITY,
}

@Serializable
enum class Flavor {
    @SerialName("supported") SUPPORTED,
    @SerialName("other") OTHER,
}

@Serializable
data class Module(
    val id: String,
    val name: String? = null,
    val version: String? = null,
    val versionCode: Long? = null,
    val author: String? = null,
    val installed: Boolean = false,
    val disabled: Boolean = false,
    val removing: Boolean = false,
    val updatePending: Boolean = false,
)

@Serializable
data class ComponentState(val component: Component, val module: Module? = null, val flavor: Flavor? = null) {
    val isReady: Boolean get() = flavor == Flavor.SUPPORTED && module != null && !module.disabled && !module.removing
}

@Serializable
data class Zygisk(val magiskBuiltin: Boolean? = null, val modules: List<String> = emptyList()) {
    val available: Boolean get() = magiskBuiltin == true || modules.isNotEmpty()
}

@Serializable
data class KeyVerdict(
    val algorithm: String,
    val serial: String,
    val root: String? = null,
    val expires: Long? = null,
    val problems: List<JsonObject> = emptyList(),
) {
    val usable: Boolean get() = problems.isEmpty()

    /**
     * A short name of each problem. A chain problem has `kind` = "chain" and the specific reason
     * (brokenLink, untrustedRoot, expired, revoked, …) in `detail`, so the detail is shown when
     * present.
     */
    fun problemKinds(): List<String> = problems.mapNotNull { problem ->
        val detail = (problem["detail"] as? JsonPrimitive)?.content
        detail ?: (problem["kind"] as? JsonPrimitive)?.content
    }
}

@Serializable
data class KeyboxVerdict(val keys: List<KeyVerdict> = emptyList(), val revocationChecked: Boolean = false) {
    val usableKeys: Int get() = keys.count { it.usable }
    fun expires(): Long? = keys.filter { it.usable }.mapNotNull { it.expires }.minOrNull()
}

@Serializable
data class FingerprintReport(
    val fingerprint: String? = null,
    val manufacturer: String? = null,
    val model: String? = null,
    val device: String? = null,
    val securityPatch: String? = null,
    val expires: Long? = null,
    val spoof: List<List<String>> = emptyList(),
    val problems: List<JsonObject> = emptyList(),
) {
    val ok: Boolean get() = problems.isEmpty()
    fun problemKinds(): List<String> = problems.mapNotNull { (it["kind"] as? JsonPrimitive)?.content }
}

@Serializable
data class InstalledFile(val sha256: String, val source: String? = null, val installedAt: Long)

@Serializable
data class StatusReport(
    val rootManager: RootManager? = null,
    val zygisk: Zygisk? = null,
    val components: List<ComponentState> = emptyList(),
    val conflicts: List<Module> = emptyList(),
    val keybox: KeyboxVerdict? = null,
    val keyboxInstalled: InstalledFile? = null,
    val fingerprint: FingerprintReport? = null,
    val fingerprintInstalled: InstalledFile? = null,
    val daemonRunning: Boolean = false,
    val staleKeys: Int = 0,
    val bootHook: Boolean = false,
    val repairedAt: Long? = null,
    val strongReady: Boolean = false,
)

@Serializable
data class ApplyReport(
    val targets: Int = 0,
    val securityPatch: String? = null,
    val spoof: List<List<JsonElement>> = emptyList(),
    val staleKeysRemoved: Int = 0,
    val daemonRestarted: Boolean = false,
    val refreshed: Boolean = false,
)

@Serializable
data class InstallReport(
    val sha256: String,
    val changed: Boolean = false,
    val verdict: KeyboxVerdict? = null,
    val fingerprint: FingerprintReport? = null,
)

/** The settings the engine reads from `--settings`, mirroring the Rust `Settings`. */
@Serializable
data class EngineSettings(
    val autoKeybox: Boolean = true,
    val autoFingerprint: Boolean = true,
    val extraPackages: List<String> = emptyList(),
    val spoofOverrides: List<List<JsonElement>> = emptyList(),
    val bootHook: Boolean = true,
)
