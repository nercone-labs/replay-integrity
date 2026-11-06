package dev.nercone.replayintegrity

import android.content.Context
import android.net.Uri
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.ApplyReport
import dev.nercone.replayintegrity.engine.BootHook
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.Engine
import dev.nercone.replayintegrity.engine.EngineException
import dev.nercone.replayintegrity.engine.EngineResult
import dev.nercone.replayintegrity.engine.FingerprintReport
import dev.nercone.replayintegrity.engine.InstallReport
import dev.nercone.replayintegrity.engine.KeyboxVerdict
import dev.nercone.replayintegrity.engine.LogLine
import dev.nercone.replayintegrity.engine.Module
import dev.nercone.replayintegrity.engine.StatusReport
import dev.nercone.replayintegrity.net.Downloader
import dev.nercone.replayintegrity.privilege.Privilege
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import dev.nercone.replayintegrity.privilege.PrivilegeException
import dev.nercone.replayintegrity.privilege.PrivilegeSelection
import dev.nercone.replayintegrity.privilege.PrivilegeSelector
import dev.nercone.replayintegrity.privilege.RootPrivilege
import dev.nercone.replayintegrity.privilege.ShizukuPrivilege
import java.io.File
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The application: the engine, the settings, the privileges and the downloader, with the
 * operations the user interface and the workers share. Operations that change the system are
 * serialized, so that a manual refresh and a scheduled one never run the engine at once.
 */
class Replay(val context: Context) {
    val engine = Engine(context)
    val settings = Settings(context)
    val shizuku = ShizukuPrivilege(context)
    val selector = PrivilegeSelector(shizuku, RootPrivilege())
    val downloader = Downloader()
    val operations = Mutex()
    val statusListLock = Mutex()

    /** What a refresh did: each part, or why it failed, and the engine log of all of it. */
    data class Refreshed(
        val keybox: InstallReport?,
        val fingerprint: InstallReport?,
        val apply: ApplyReport,
        val hook: BootHook?,
        val problems: List<String>,
        val log: List<LogLine>,
    )

    /** What a repair did. */
    data class Repaired(val apply: ApplyReport, val restarted: Boolean, val log: List<LogLine>)

    /** A file the user chose, checked by the engine before it is installed. */
    sealed interface Candidate {
        val file: File
        val name: String

        data class Keybox(override val file: File, override val name: String, val verdict: KeyboxVerdict) : Candidate
        data class Fingerprint(override val file: File, override val name: String, val report: FingerprintReport) : Candidate
    }

    /**
     * Chooses the privilege. With `interactive`, a missing permission is asked for while the
     * user is here, once: Shizuku keeps no refusal, so a declined permission is remembered and
     * not asked for again until the privilege choice changes. Callers that run without the
     * user, such as the workers, leave `interactive` false, so that no dialog opens.
     */
    suspend fun selectPrivilege(interactive: Boolean = false): PrivilegeSelection {
        val values = settings.values.value
        val selection = selector.select(values.privilege, interactive && !values.permissionDeclined)
        if (selection.declined) settings.update { it.copy(permissionDeclined = true) }
        return selection
    }

    /** Whether the privilege choice may use Shizuku, and a Shizuku binder may arrive. */
    fun awaitsShizuku(): Boolean = settings.values.value.privilege != PrivilegeChoice.ROOT && shizuku.mayStart()

    suspend fun privilege(): Privilege = selectPrivilege().privilege ?: throw PrivilegeException("no privilege can run the engine as root")

    /**
     * The certificate status list, downloaded at most every `STATUS_LIST_MAX_AGE_MILLIS`. When
     * it cannot be downloaded, a copy up to `STATUS_LIST_STALE_MILLIS` old is used; without
     * one, `null`, and the engine reports that revocation was not checked.
     */
    suspend fun statusList(): File? = statusListLock.withLock {
        val file = File(engine.directory, STATUS_LIST)
        val age = withContext(Dispatchers.IO) { if (file.isFile) System.currentTimeMillis() - file.lastModified() else Long.MAX_VALUE }
        if (age in 0 until STATUS_LIST_MAX_AGE_MILLIS) return@withLock file
        try {
            engine.write(STATUS_LIST, downloader.statusList().bytes)
        } catch (_: IOException) {
            file.takeIf { age in 0 until STATUS_LIST_STALE_MILLIS }
        }
    }

    suspend fun status(): EngineResult<StatusReport> = engine.status(privilege(), statusList())

    /**
     * Downloads the keybox and the fingerprint (each unless the user keeps their own), installs
     * what was fetched, then applies the configuration and installs or removes the boot hook. A
     * download or installation failure is a problem, not an error: the installed files stay
     * and the apply still runs, so a bad network or a bad mirror never leaves the device worse
     * off. The keybox is taken from the first source that offers one at least as good as the
     * installed one (`refreshKeybox`).
     */
    suspend fun refresh(): Refreshed = operations.withLock {
        val privilege = privilege()
        val values = settings.values.value
        val problems = mutableListOf<String>()
        val log = mutableListOf<LogLine>()
        val status = statusList()
        val keybox = if (values.autoKeybox) refreshKeybox(privilege, values.keyboxSources(), status, problems, log) else null
        val fingerprint = if (values.autoFingerprint) {
            attempt("fingerprint", problems) {
                val fetched = downloader.fingerprint(values.fingerprintUrl)
                engine.installFingerprint(privilege, engine.write(FINGERPRINT, fetched.bytes), fetched.source, values.engine()).also { log += it.log }.value
            }
        } else {
            null
        }
        // Restarting the keystore ends the Play services and Play Store processes, which is
        // disruptive, so it is done only when there is a reason: an input changed, or this is
        // the first apply. A scheduled run on an unchanged device then re-applies quietly.
        val changed = keybox?.changed == true || fingerprint?.changed == true
        val restart = values.restartOnChange && (changed || !values.applied)
        val apply = engine.apply(privilege, values.engine(), restart).also { log += it.log }.value
        settings.update { it.copy(applied = true) }
        val hook = attempt("boot hook", problems) { synchronizeHook(privilege).also { log += it.log }.value }
        settings.update { it.copy(lastRefreshAt = System.currentTimeMillis(), lastRefreshProblems = problems) }
        Refreshed(keybox, fingerprint, apply, hook, problems, log)
    }

    /**
     * Offers the keybox of each source, in order, until the engine installs one or finds it is
     * the installed one. The engine declines a keybox that ranks below the installed one
     * (`--no-downgrade`), so a mirror that serves a revoked or broken keybox never replaces a
     * working one, and the next source is tried. A source that fails or is declined is a
     * problem only when no source succeeds: a working fallback leaves nothing to fix. Returns
     * the report of the source that succeeded, or of the last one declined.
     */
    suspend fun refreshKeybox(privilege: Privilege, sources: List<String>, status: File?, problems: MutableList<String>, log: MutableList<LogLine>): InstallReport? {
        val failures = mutableListOf<String>()
        var declined: InstallReport? = null
        for (url in sources) {
            val report = attempt(url, failures) {
                val fetched = downloader.keybox(url)
                val result = try {
                    engine.installKeybox(privilege, engine.write(KEYBOX, fetched.bytes), fetched.source, status, noDowngrade = true)
                } catch (error: EngineException) {
                    log += error.log
                    throw error
                }
                log += result.log
                result.value
            } ?: continue
            val reason = report.declined ?: return report
            failures += "$url: $reason"
            declined = report
        }
        problems += failures.map { "keybox: $it" }
        return declined
    }

    /**
     * Re-applies the configuration without downloading anything: rebuild the target list,
     * re-apply the spoof flags and the security patch, and remove the stale persisted keys that
     * keep an application on an old keybox. With `restart`, the keystore daemon and the Play
     * processes are restarted; otherwise only when stale keys were removed, which the running
     * daemon may still hold, and the settings allow restarts.
     */
    suspend fun repair(restart: Boolean): Repaired = operations.withLock {
        val privilege = privilege()
        val values = settings.values.value
        val applied = engine.apply(privilege, values.engine(), restart)
        settings.update { it.copy(applied = true) }
        val late = !restart && values.restartOnChange && applied.value.staleKeysRemoved > 0
        val restarted = if (late) engine.restart(privilege) else null
        Repaired(applied.value, applied.value.daemonRestarted || restarted?.value?.restarted == true, applied.log + restarted?.log.orEmpty())
    }

    suspend fun restart(): EngineResult<Boolean> = operations.withLock {
        val result = engine.restart(privilege())
        EngineResult(result.value.restarted, result.log)
    }

    /** Installs or removes the boot hook, with or without the package watcher, as the settings say. */
    suspend fun synchronizeHook(privilege: Privilege): EngineResult<BootHook> {
        val values = settings.values.value
        return if (values.bootHook) engine.installHook(privilege, values.watchPackages) else engine.removeHook(privilege)
    }

    suspend fun setBootHook(enabled: Boolean): EngineResult<BootHook> = operations.withLock {
        settings.update { it.copy(bootHook = enabled) }
        synchronizeHook(privilege())
    }

    suspend fun setWatchPackages(enabled: Boolean): EngineResult<BootHook> = operations.withLock {
        settings.update { it.copy(watchPackages = enabled) }
        synchronizeHook(privilege())
    }

    /** Disables the conflicting modules; they stop running at the next boot. */
    suspend fun disableConflicts(): EngineResult<List<Module>> = operations.withLock { engine.disableConflicts(privilege()) }

    /** Copies a file the user chose into the engine directory, refusing files larger than `limit`. */
    suspend fun copy(uri: Uri, name: String, limit: Int): File = withContext(Dispatchers.IO) {
        val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
            val buffer = java.io.ByteArrayOutputStream()
            val chunk = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(chunk)
                if (read < 0) break
                if (buffer.size() + read > limit) throw IOException("the file is larger than ${limit / 1024 / 1024} MiB")
                buffer.write(chunk, 0, read)
            }
            buffer.toByteArray()
        } ?: throw IOException("the file cannot be opened")
        engine.write(name, bytes)
    }

    /** Checks a keybox the user chose, without installing it. */
    suspend fun inspectKeybox(uri: Uri, name: String): Candidate.Keybox {
        val file = copy(uri, IMPORTED_KEYBOX, MAX_IMPORT_BYTES)
        return Candidate.Keybox(file, name, engine.inspectKeybox(file, statusList()).value)
    }

    /** Checks a fingerprint the user chose, without installing it. */
    suspend fun inspectFingerprint(uri: Uri, name: String): Candidate.Fingerprint {
        val file = copy(uri, IMPORTED_FINGERPRINT, MAX_IMPORT_BYTES)
        return Candidate.Fingerprint(file, name, engine.inspectFingerprint(file).value)
    }

    /**
     * Installs a checked file and applies the configuration. A file the user chose would be
     * replaced by the next refresh, so its automatic refresh is turned off.
     */
    suspend fun install(candidate: Candidate): Repaired = operations.withLock {
        val privilege = privilege()
        val source = "file:${candidate.name}"
        val values = settings.values.value
        val installed = when (candidate) {
            is Candidate.Keybox -> engine.installKeybox(privilege, candidate.file, source, statusList(), noDowngrade = false)
            is Candidate.Fingerprint -> engine.installFingerprint(privilege, candidate.file, source, values.engine())
        }
        settings.update {
            when (candidate) {
                is Candidate.Keybox -> it.copy(autoKeybox = false, applied = true)
                is Candidate.Fingerprint -> it.copy(autoFingerprint = false, applied = true)
            }
        }
        val applied = engine.apply(privilege, values.engine(), values.restartOnChange && installed.value.changed)
        Repaired(applied.value, applied.value.daemonRestarted, installed.log + applied.log)
    }

    /** Installs a module zip with the root manager; it takes effect at the next boot. */
    suspend fun installModule(component: Component, uri: Uri): EngineResult<String> = operations.withLock {
        val zip = copy(uri, MODULE, MAX_MODULE_BYTES)
        try {
            val result = engine.installModule(privilege(), component, zip)
            EngineResult(result.value.output, result.log)
        } finally {
            withContext(Dispatchers.IO) { zip.delete() }
        }
    }

    /** Runs `block`, turning a failure into a problem named `what`. */
    suspend fun <T> attempt(what: String, problems: MutableList<String>, block: suspend () -> T): T? = try {
        block()
    } catch (error: Exception) {
        if (error is kotlinx.coroutines.CancellationException) throw error
        problems += "$what: ${error.message ?: error.toString()}"
        null
    }

    companion object {
        const val STATUS_LIST = "status.json"
        const val KEYBOX = "keybox.xml"
        const val FINGERPRINT = "fingerprint.prop"
        const val IMPORTED_KEYBOX = "imported-keybox.xml"
        const val IMPORTED_FINGERPRINT = "imported-fingerprint.prop"
        const val MODULE = "module.zip"
        const val MAX_IMPORT_BYTES = 1024 * 1024
        const val MAX_MODULE_BYTES = 64 * 1024 * 1024
        const val STATUS_LIST_MAX_AGE_MILLIS = 60 * 60 * 1000L
        const val STATUS_LIST_STALE_MILLIS = 7 * 24 * 60 * 60 * 1000L
    }
}
