package dev.nercone.replayintegrity.engine

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

// The data exchanged with the engine. Every type mirrors a type of the `replay` crate and its
// JSON form; see crates/replay/src/engine.rs. Unknown fields are ignored, so that a field the
// engine adds later does not break an older reader.

object EngineJson {
    val json = Json { ignoreUnknownKeys = true; explicitNulls = false; encodeDefaults = true; coerceInputValues = true }
}

@Serializable
enum class LogLevel {
    @SerialName("info") INFO,
    @SerialName("warning") WARNING,
    @SerialName("error") ERROR,
}

@Serializable
data class LogLine(val time: Long, val level: LogLevel = LogLevel.INFO, val message: String)

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
    ;

    /** The engine's name of the component on its command line. */
    val argument: String get() = if (this == KEYSTORE) "keystore" else "integrity"
}

@Serializable
enum class Flavor {
    @SerialName("supported") SUPPORTED,
    @SerialName("other") OTHER,
}

@Serializable
enum class TargetMode {
    @SerialName("auto") AUTO,
    @SerialName("generate") GENERATE,
    @SerialName("patch") PATCH,
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
) {
    /** Whether the module runs after the next boot. */
    val active: Boolean get() = !disabled && !removing
}

@Serializable
data class ComponentState(val component: Component, val module: Module? = null, val flavor: Flavor? = null) {
    /** Whether the supported module is installed and active, possibly waiting for a reboot. */
    val ready: Boolean get() = flavor == Flavor.SUPPORTED && module?.active == true
}

@Serializable
data class Zygisk(val magiskBuiltin: Boolean? = null, val modules: List<String> = emptyList()) {
    val available: Boolean get() = magiskBuiltin == true || modules.isNotEmpty()
}

/**
 * A problem of a key or a fingerprint. The engine tags each with `kind`; a chain problem has
 * `kind` "chain" and the specific reason in `detail` (brokenLink, untrustedRoot, expired,
 * revoked, ...). Other fields depend on the kind and are kept as they are.
 */
@Serializable(with = Problem.Serializer::class)
data class Problem(val fields: JsonObject) {
    val kind: String get() = (fields["kind"] as? JsonPrimitive)?.content.orEmpty()
    val detail: String? get() = (fields["detail"] as? JsonPrimitive)?.content

    /** The most specific name: the detail of a chain problem, or the kind. */
    val name: String get() = detail ?: kind

    fun text(key: String): String? = (fields[key] as? JsonPrimitive)?.content

    fun number(key: String): Long? = (fields[key] as? JsonPrimitive)?.longOrNull

    object Serializer : kotlinx.serialization.KSerializer<Problem> {
        override val descriptor = JsonObject.serializer().descriptor
        override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: Problem) = JsonObject.serializer().serialize(encoder, value.fields)
        override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder) = Problem(JsonObject.serializer().deserialize(decoder))
    }

    companion object {
        const val KIND_CHAIN = "chain"
        const val KIND_MISMATCH = "keyMismatch"
        const val DETAIL_REVOKED = "revoked"
        const val DETAIL_EXPIRED = "expired"
    }
}

@Serializable
data class KeyVerdict(
    val algorithm: String,
    val serial: String = "",
    val root: String? = null,
    val expires: Long? = null,
    val problems: List<Problem> = emptyList(),
) {
    val usable: Boolean get() = problems.isEmpty()
}

/**
 * The verdict of a keybox. `defect` says why the file is not a well-formed keybox, when the
 * engine recovered its keys from broken markup: a keystore daemon reads no key from such a file.
 */
@Serializable
data class KeyboxVerdict(val keys: List<KeyVerdict> = emptyList(), val revocationChecked: Boolean = false, val defect: String? = null) {
    val usableKeys: Int get() = keys.count { it.usable }

    /** Whether a usable key of `algorithm` (ECDSA or RSA) is present. */
    fun hasUsable(algorithm: String): Boolean = keys.any { it.algorithm.equals(algorithm, ignoreCase = true) && it.usable }

    /**
     * Whether the keybox can reach STRONG: a usable EC key, in a file the daemon can read. Play
     * Integrity attests with EC; TEESimulator-RS signs RSA requests with the EC key when there
     * is no RSA key, so an RSA key is not needed (`KeyboxVerdict::is_strong_capable`).
     */
    val strongCapable: Boolean get() = defect == null && hasUsable(ECDSA)

    /**
     * Whether the keybox reaches STRONG once installed: a usable EC key. An offered keybox with
     * a `defect` is written again as a well-formed one when it is installed, so its markup does
     * not count, as in the engine's `KeyboxVerdict::rank`.
     */
    val strongCapableOnceInstalled: Boolean get() = hasUsable(ECDSA)

    /** Whether any key is revoked: the keybox leaked and Google listed it. */
    val revoked: Boolean get() = keys.any { key -> key.problems.any { it.detail == Problem.DETAIL_REVOKED } }

    /** The soonest a usable key stops being valid. */
    val expires: Long? get() = keys.filter { it.usable }.mapNotNull { it.expires }.minOrNull()

    companion object {
        /** The names of `KeyAlgorithm::name` of the keybox crate. */
        const val ECDSA = "ecdsa"
        const val RSA = "rsa"
    }
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
    val problems: List<Problem> = emptyList(),
) {
    val ok: Boolean get() = problems.isEmpty()

    /** The spoof flags of the file, by key, as booleans ("1" or "true"). */
    fun spoofFlags(): Map<String, Boolean> = spoof.mapNotNull { pair ->
        val key = pair.getOrNull(0) ?: return@mapNotNull null
        val value = pair.getOrNull(1)?.trim() ?: return@mapNotNull null
        key to (value == "1" || value.equals("true", ignoreCase = true))
    }.toMap()
}

@Serializable
data class InstalledFile(val sha256: String, val source: String? = null, val installedAt: Long)

@Serializable
data class Target(@SerialName("package") val packageName: String, val mode: TargetMode = TargetMode.AUTO)

@Serializable
data class TargetList(val targets: List<Target> = emptyList())

@Serializable
data class PersistedKey(val uid: Long, val alias: String)

@Serializable
data class DaemonState(val daemons: List<Long> = emptyList(), val supervisors: List<Long> = emptyList()) {
    val running: Boolean get() = daemons.isNotEmpty()
}

/**
 * The boot scripts, mirroring the Rust `BootHook`: `watches` says whether the service script that
 * starts the package watcher is installed, and `watcher` is the process ID of the running watcher.
 */
@Serializable
data class BootHook(
    val managers: List<RootManager> = emptyList(),
    val scripts: List<String> = emptyList(),
    val watches: Boolean = false,
    val watcher: Long? = null,
) {
    val installed: Boolean get() = scripts.isNotEmpty()
}

/**
 * The settings the engine reads from `--settings`, mirroring the Rust `Settings`. A spoof
 * override is a two-element array `[key, value]`, as serde writes a Rust tuple.
 */
@Serializable
data class EngineSettings(
    val extraPackages: List<String> = emptyList(),
    val excludedPackages: List<String> = emptyList(),
    val targetMode: TargetMode = TargetMode.AUTO,
    /** The mode of the Play stack, which the engine defaults to generating its keys. */
    val playTargetMode: TargetMode = TargetMode.GENERATE,
    val spoofOverrides: List<List<JsonElement>> = emptyList(),
) {
    /** The overrides by key; a malformed entry is left out. */
    fun overrides(): Map<String, Boolean> = spoofOverrides.mapNotNull { pair ->
        val key = (pair.getOrNull(0) as? JsonPrimitive)?.content ?: return@mapNotNull null
        val value = (pair.getOrNull(1) as? JsonPrimitive)?.booleanOrNull ?: return@mapNotNull null
        key to value
    }.toMap()

    /** Whether `other` makes the engine do the same: the order of the lists does not matter. */
    fun sameAs(other: EngineSettings): Boolean =
        extraPackages.toSet() == other.extraPackages.toSet() &&
            excludedPackages.toSet() == other.excludedPackages.toSet() &&
            targetMode == other.targetMode &&
            playTargetMode == other.playTargetMode &&
            overrides() == other.overrides()

    companion object {
        fun override(key: String, value: Boolean): List<JsonElement> = listOf(JsonPrimitive(key), JsonPrimitive(value))
    }
}

@Serializable
data class StatusReport(
    val engineVersion: String? = null,
    val firstApiLevel: Int? = null,
    val rootManagers: List<RootManager> = emptyList(),
    val zygisk: Zygisk? = null,
    val components: List<ComponentState> = emptyList(),
    val conflicts: List<Module> = emptyList(),
    val keybox: KeyboxVerdict? = null,
    val keyboxInstalled: InstalledFile? = null,
    val fingerprint: FingerprintReport? = null,
    val fingerprintInstalled: InstalledFile? = null,
    val integrity: FingerprintReport? = null,
    val spoof: List<List<JsonElement>> = emptyList(),
    val securityPatch: String? = null,
    val targets: TargetList? = null,
    val persistedKeys: Int = 0,
    val staleKeys: List<PersistedKey> = emptyList(),
    val daemon: DaemonState = DaemonState(),
    val bootHook: BootHook = BootHook(),
    val appliedAt: Long? = null,
    val bootedAt: Long? = null,
    /** The settings `apply` saved last, which the boot hook applies. */
    val settings: EngineSettings = EngineSettings(),
    val missingCapabilities: List<String> = emptyList(),
    val strongReady: Boolean = false,
) {
    fun component(component: Component): ComponentState? = components.find { it.component == component }

    /** The spoof flags `apply` writes, by key. */
    fun appliedSpoof(): Map<String, Boolean> = spoof.mapNotNull { pair ->
        val key = (pair.getOrNull(0) as? JsonPrimitive)?.content ?: return@mapNotNull null
        val value = (pair.getOrNull(1) as? JsonPrimitive)?.booleanOrNull ?: return@mapNotNull null
        key to value
    }.toMap()

    /**
     * The flags of the live `custom.pif.prop` that differ from those `apply` writes: a script of
     * the module rewrote the file since the last apply.
     */
    fun driftedSpoof(): List<String> {
        val live = integrity?.spoofFlags() ?: return emptyList()
        return appliedSpoof().filter { (key, value) -> live[key] != null && live[key] != value }.keys.toList()
    }

    /** The one root manager, or `null` when none or several are installed. */
    val rootManager: RootManager? get() = rootManagers.singleOrNull()
}

@Serializable
data class ApplyReport(
    val targets: Int = 0,
    val targetsRebuilt: Boolean = false,
    val securityPatch: String? = null,
    val spoof: List<List<JsonElement>> = emptyList(),
    val staleKeysRemoved: Int = 0,
    /** Stale keys kept because the keystore could not delete them yet; the next repair tries again. */
    val staleKeysKept: Int = 0,
    /** Whether the installed keybox was not well-formed and was written again. */
    val keyboxRepaired: Boolean = false,
    val daemonRestarted: Boolean = false,
)

@Serializable
data class InstallReport(
    val sha256: String,
    val changed: Boolean = false,
    val verdict: KeyboxVerdict? = null,
    /** The keys of the offered keybox that were not written, because others are usable. */
    val droppedKeys: Int = 0,
    /** Why the offered file was not installed, when the installed keybox ranked higher. */
    val declined: String? = null,
    val fingerprint: FingerprintReport? = null,
)

@Serializable
data class RestartReport(val restarted: Boolean = false)

@Serializable
data class ModuleOutput(val output: String = "")

/** The spoof flags of PlayIntegrityFork that the engine writes, in its order. */
object SpoofFlag {
    val ALL = listOf("spoofBuild", "spoofProps", "spoofProvider", "spoofSignature", "spoofVendingFinger", "spoofVendingSdk")
}
