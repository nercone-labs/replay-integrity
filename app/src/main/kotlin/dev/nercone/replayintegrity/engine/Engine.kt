package dev.nercone.replayintegrity.engine

import android.content.Context
import dev.nercone.replayintegrity.privilege.Privilege
import dev.nercone.replayintegrity.privilege.ProcessRunner
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer

/** A failed engine command, with the engine log of the attempt. */
class EngineException(val kind: String, message: String, val log: List<LogLine>) : Exception(message) {
    companion object {
        /** The engine runs as root, but the root manager removed the capabilities it needs. */
        const val RESTRICTED = "restricted"
        const val TIMEOUT = "timeout"
        const val OUTPUT = "output"
    }
}

/** The successful result of an engine command, with the engine log. */
data class EngineResult<T>(val value: T, val log: List<LogLine>)

/**
 * The Rust engine (`replay`), packaged as `libreplay.so` in the native library directory.
 * Commands that read or change the system run as root through a `Privilege`; checking a
 * downloaded keybox or fingerprint runs as the application itself.
 *
 * The application downloads the keybox, the fingerprint and the certificate status list with
 * ordinary TLS and passes their paths to the engine; the engine performs no network access.
 */
class Engine(val context: Context) {
    val executable: String = File(context.applicationInfo.nativeLibraryDir, EXECUTABLE).absolutePath
    val json = EngineJson.json

    /** The directory of the files handed to the engine. */
    val directory: File get() = File(context.cacheDir, DIRECTORY).apply { mkdirs() }

    fun decode(output: String): EngineResponse {
        val line = output.lineSequence().lastOrNull { it.startsWith("{") }
            ?: throw EngineException(EngineException.OUTPUT, "the engine printed no result: ${output.take(500)}", emptyList())
        return try {
            json.decodeFromString(EngineResponse.serializer(), line)
        } catch (error: SerializationException) {
            throw EngineException(EngineException.OUTPUT, "the engine printed an invalid result: ${error.message}", emptyList())
        } catch (error: IllegalArgumentException) {
            throw EngineException(EngineException.OUTPUT, "the engine printed an invalid result: ${error.message}", emptyList())
        }
    }

    fun <T> result(response: EngineResponse, serializer: KSerializer<T>): EngineResult<T> {
        val error = response.error
        if (!response.ok || error != null) {
            throw EngineException(error?.kind ?: "unknown", error?.message ?: "the engine failed", response.log)
        }
        val value = response.result ?: throw EngineException(EngineException.OUTPUT, "the engine returned no result", response.log)
        return try {
            EngineResult(json.decodeFromJsonElement(serializer, value), response.log)
        } catch (error: SerializationException) {
            throw EngineException(EngineException.OUTPUT, "the engine returned an unexpected result: ${error.message}", response.log)
        } catch (error: IllegalArgumentException) {
            throw EngineException(EngineException.OUTPUT, "the engine returned an unexpected result: ${error.message}", response.log)
        }
    }

    /** Runs the engine as the application, for checking files. */
    suspend fun <T> run(arguments: List<String>, serializer: KSerializer<T>, timeoutMillis: Long = TIMEOUT_MILLIS): EngineResult<T> =
        withContext(Dispatchers.IO) {
            val output = ProcessRunner.run(listOf(executable) + arguments, timeoutMillis)
            if (output.exitCode == ProcessRunner.TIMEOUT_EXIT_CODE && output.stdout.isBlank()) {
                throw EngineException(EngineException.TIMEOUT, "the engine did not finish in time", emptyList())
            }
            result(decode(output.stdout), serializer)
        }

    /** Runs the engine through `privilege`. */
    suspend fun <T> run(privilege: Privilege, arguments: List<String>, serializer: KSerializer<T>, timeoutMillis: Long = TIMEOUT_MILLIS): EngineResult<T> {
        val output = privilege.execute(listOf(executable) + arguments, timeoutMillis)
        if (output.exitCode == ProcessRunner.START_FAILURE_EXIT_CODE && output.stdout.isBlank()) {
            throw EngineException(EngineException.OUTPUT, "the engine could not be started: ${output.stderr.take(500)}", emptyList())
        }
        if (output.exitCode == ProcessRunner.TIMEOUT_EXIT_CODE && output.stdout.isBlank()) {
            throw EngineException(EngineException.TIMEOUT, "the engine did not finish in time: ${output.stderr.take(500)}", emptyList())
        }
        return result(decode(output.stdout), serializer)
    }

    suspend fun version(): EngineResult<VersionReport> = run(listOf("version"), VersionReport.serializer())

    suspend fun status(privilege: Privilege, statusList: File?): EngineResult<StatusReport> =
        run(privilege, listOf("status") + statusArguments(statusList), StatusReport.serializer())

    suspend fun inspectKeybox(file: File, statusList: File?): EngineResult<KeyboxVerdict> =
        run(listOf("inspect-keybox", file.absolutePath) + statusArguments(statusList), KeyboxVerdict.serializer())

    suspend fun inspectFingerprint(file: File): EngineResult<FingerprintReport> =
        run(listOf("inspect-fingerprint", file.absolutePath), FingerprintReport.serializer())

    suspend fun installKeybox(privilege: Privilege, file: File, source: String?, statusList: File?): EngineResult<InstallReport> =
        run(privilege, listOf("install-keybox", file.absolutePath) + sourceArguments(source) + statusArguments(statusList), InstallReport.serializer())

    suspend fun installFingerprint(privilege: Privilege, file: File, source: String?, settings: EngineSettings): EngineResult<InstallReport> =
        run(privilege, listOf("install-fingerprint", file.absolutePath) + sourceArguments(source) + settingsArguments(settings), InstallReport.serializer())

    suspend fun apply(privilege: Privilege, settings: EngineSettings, restart: Boolean): EngineResult<ApplyReport> {
        val arguments = listOf("apply") + (if (restart) emptyList() else listOf("--no-restart")) + settingsArguments(settings)
        return run(privilege, arguments, ApplyReport.serializer(), LONG_TIMEOUT_MILLIS)
    }

    suspend fun restart(privilege: Privilege): EngineResult<RestartReport> =
        run(privilege, listOf("restart"), RestartReport.serializer(), LONG_TIMEOUT_MILLIS)

    suspend fun staleKeys(privilege: Privilege): EngineResult<List<PersistedKey>> =
        run(privilege, listOf("stale-keys"), ListSerializer(PersistedKey.serializer()))

    suspend fun installModule(privilege: Privilege, component: Component, zip: File): EngineResult<ModuleOutput> =
        run(privilege, listOf("install-module", component.argument, zip.absolutePath), ModuleOutput.serializer(), LONG_TIMEOUT_MILLIS)

    /**
     * Installs the boot scripts, with a copy of the engine that survives updates of the application.
     * With `watch`, the package watcher is started at every boot, and now when it does not run.
     */
    suspend fun installHook(privilege: Privilege, watch: Boolean): EngineResult<BootHook> =
        run(privilege, listOf("hook", "install", "--package", context.packageName) + (if (watch) emptyList() else listOf("--no-watch")), BootHook.serializer())

    /** Disables the conflicting modules from the next boot; returns them as they are afterwards. */
    suspend fun disableConflicts(privilege: Privilege): EngineResult<List<Module>> =
        run(privilege, listOf("disable-conflicts"), ListSerializer(Module.serializer()))

    suspend fun removeHook(privilege: Privilege): EngineResult<BootHook> = run(privilege, listOf("hook", "remove"), BootHook.serializer())

    fun statusArguments(statusList: File?): List<String> = statusList?.let { listOf("--status", it.absolutePath) } ?: emptyList()

    fun sourceArguments(source: String?): List<String> = source?.let { listOf("--source", it) } ?: emptyList()

    /** Writes `settings` for the engine and returns `--settings` with its path. */
    suspend fun settingsArguments(settings: EngineSettings): List<String> =
        listOf("--settings", write(SETTINGS, json.encodeToString(EngineSettings.serializer(), settings).toByteArray()).absolutePath)

    /** Writes `bytes` to a file named `name` that the engine can read, replacing it whole. */
    suspend fun write(name: String, bytes: ByteArray): File = withContext(Dispatchers.IO) {
        val file = File(directory, name)
        val temporary = File(directory, "$name.tmp")
        temporary.writeBytes(bytes)
        if (!temporary.renameTo(file)) throw java.io.IOException("cannot write $file")
        file
    }

    companion object {
        const val EXECUTABLE = "libreplay.so"
        const val DIRECTORY = "engine"
        const val SETTINGS = "settings.json"
        const val TIMEOUT_MILLIS = 60_000L

        /** Applying restarts the keystore daemon and ends processes, and installing a module runs the root manager. */
        const val LONG_TIMEOUT_MILLIS = 5 * 60_000L
    }
}

@kotlinx.serialization.Serializable
data class VersionReport(val version: String)
