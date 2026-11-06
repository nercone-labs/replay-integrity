package dev.nercone.replayintegrity.engine

import android.content.Context
import dev.nercone.replayintegrity.privilege.Privilege
import dev.nercone.replayintegrity.privilege.ProcessRunner
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/** A failed engine command, with the engine log of the attempt. */
class EngineException(val kind: String, message: String, val log: List<LogLine>) : Exception(message)

/** The successful result of an engine command, with the engine log. */
data class EngineResult<T>(val value: T, val log: List<LogLine>)

/**
 * The Rust engine (`replay`), packaged as `libreplay.so` in the native library directory.
 * Commands that read or change the system run as root through a [Privilege]; checking a
 * downloaded keybox or fingerprint runs as the application itself.
 *
 * The application downloads the keybox, the fingerprint and the certificate status list with
 * ordinary TLS and passes their paths to the engine; the engine performs no network access.
 */
class Engine(context: Context) {
    val executable: String = File(context.applicationInfo.nativeLibraryDir, EXECUTABLE).absolutePath
    val filesDir: File = context.filesDir
    val cacheDir: File = context.cacheDir
    val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

    fun decode(output: String): EngineResponse {
        val line = output.lineSequence().lastOrNull { it.startsWith("{") }
            ?: throw EngineException("output", "the engine printed no result: ${output.take(500)}", emptyList())
        return try {
            json.decodeFromString(EngineResponse.serializer(), line)
        } catch (error: SerializationException) {
            throw EngineException("output", "the engine printed an invalid result: ${error.message}", emptyList())
        }
    }

    fun <T> result(response: EngineResponse, serializer: KSerializer<T>): EngineResult<T> {
        val error = response.error
        if (!response.ok || error != null) {
            throw EngineException(error?.kind ?: "unknown", error?.message ?: "the engine failed", response.log)
        }
        val value = response.result ?: throw EngineException("output", "the engine returned no result", response.log)
        return EngineResult(json.decodeFromJsonElement(serializer, value), response.log)
    }

    /** Runs the engine as the application (no privilege), for checking downloaded files. */
    suspend fun <T> run(arguments: List<String>, serializer: KSerializer<T>, timeoutMillis: Long = TIMEOUT_MILLIS): EngineResult<T> =
        withContext(Dispatchers.IO) {
            val output = ProcessRunner.run(listOf(executable) + arguments, timeoutMillis)
            result(decode(output.stdout + "\n" + output.stderr), serializer)
        }

    /** Runs the engine as root through [privilege]. */
    suspend fun <T> run(privilege: Privilege, arguments: List<String>, serializer: KSerializer<T>, timeoutMillis: Long = TIMEOUT_MILLIS): EngineResult<T> {
        val output = privilege.execute(listOf(executable) + arguments, timeoutMillis)
        if (output.exitCode == ProcessRunner.TIMEOUT_EXIT_CODE && output.stdout.isBlank()) {
            throw EngineException("timeout", "the engine did not finish in time: ${output.stderr.take(500)}", emptyList())
        }
        return result(decode(output.stdout), serializer)
    }

    suspend fun status(privilege: Privilege, statusList: File?): EngineResult<StatusReport> =
        run(privilege, listOf("status") + statusArguments(statusList), StatusReport.serializer())

    suspend fun inspectKeybox(file: File, statusList: File?): EngineResult<KeyboxVerdict> =
        run(listOf("inspect-keybox", file.absolutePath) + statusArguments(statusList), KeyboxVerdict.serializer())

    suspend fun inspectFingerprint(file: File): EngineResult<FingerprintReport> =
        run(listOf("inspect-fingerprint", file.absolutePath), FingerprintReport.serializer())

    suspend fun installKeybox(privilege: Privilege, file: File, source: String?, statusList: File?): EngineResult<InstallReport> =
        run(privilege, listOf("install-keybox", file.absolutePath) + source(source) + statusArguments(statusList), InstallReport.serializer(), LONG_TIMEOUT_MILLIS)

    suspend fun installFingerprint(privilege: Privilege, file: File, source: String?, settings: File?): EngineResult<InstallReport> =
        run(privilege, listOf("install-fingerprint", file.absolutePath) + source(source) + settingsArguments(settings), InstallReport.serializer())

    suspend fun apply(privilege: Privilege, settings: File?, restart: Boolean): EngineResult<ApplyReport> =
        run(privilege, listOf("apply") + (if (restart) emptyList() else listOf("--no-restart")) + settingsArguments(settings), ApplyReport.serializer(), LONG_TIMEOUT_MILLIS)

    suspend fun restart(privilege: Privilege): EngineResult<RestartReport> =
        run(privilege, listOf("restart"), RestartReport.serializer(), LONG_TIMEOUT_MILLIS)

    suspend fun installModule(privilege: Privilege, component: Component, zip: File): EngineResult<ModuleOutput> =
        run(privilege, listOf("install-module", if (component == Component.KEYSTORE) "keystore" else "integrity", zip.absolutePath), ModuleOutput.serializer(), LONG_TIMEOUT_MILLIS)

    suspend fun installHook(privilege: Privilege): EngineResult<BootHook> =
        run(privilege, listOf("hook", "install", "--executable", executable), BootHook.serializer())

    suspend fun removeHook(privilege: Privilege): EngineResult<BootHook> =
        run(privilege, listOf("hook", "remove"), BootHook.serializer())

    fun statusArguments(statusList: File?): List<String> = statusList?.let { listOf("--status", it.absolutePath) } ?: emptyList()

    fun settingsArguments(settings: File?): List<String> = settings?.let { listOf("--settings", it.absolutePath) } ?: emptyList()

    fun source(source: String?): List<String> = source?.let { listOf("--source", it) } ?: emptyList()

    /** Writes [text] to a cache file, for passing a setting to the engine. */
    suspend fun writeCache(name: String, text: String): File = withContext(Dispatchers.IO) {
        File(cacheDir, name).apply { writeText(text) }
    }

    companion object {
        const val EXECUTABLE = "libreplay.so"
        const val TIMEOUT_MILLIS = 60_000L
        const val LONG_TIMEOUT_MILLIS = 5 * 60_000L
    }
}

@kotlinx.serialization.Serializable
data class RestartReport(val restarted: Boolean = false)

@kotlinx.serialization.Serializable
data class ModuleOutput(val output: String = "")

@kotlinx.serialization.Serializable
data class BootHook(val managers: List<RootManager> = emptyList(), val scripts: List<String> = emptyList()) {
    val installed: Boolean get() = scripts.isNotEmpty()
}
