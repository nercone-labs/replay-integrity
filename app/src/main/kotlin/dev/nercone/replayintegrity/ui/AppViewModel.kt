package dev.nercone.replayintegrity.ui

import android.app.Application
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.nercone.replayintegrity.Replay
import dev.nercone.replayintegrity.ReplayApplication
import dev.nercone.replayintegrity.boot.RefreshWorker
import dev.nercone.replayintegrity.config.Protection
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.EngineException
import dev.nercone.replayintegrity.engine.KeyRemovalReport
import dev.nercone.replayintegrity.engine.LogLine
import dev.nercone.replayintegrity.engine.Module
import dev.nercone.replayintegrity.engine.OutdatedKey
import dev.nercone.replayintegrity.engine.StatusReport
import dev.nercone.replayintegrity.net.Downloader
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import dev.nercone.replayintegrity.privilege.PrivilegeSelection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** An operation the user started, shown while it runs. Only one runs at a time. */
enum class Operation { PREPARING, CHECKING, REFRESHING, REPAIRING, RESTARTING, INSPECTING, INSTALLING, INSTALLING_MODULE, CONFIGURING_BOOT, DISABLING_CONFLICTS, REMOVING_KEY }

/** What the user is told about the last operation. */
sealed interface Outcome {
    data class Refreshed(val refreshed: Replay.Refreshed) : Outcome
    data class Repaired(val repaired: Replay.Repaired) : Outcome
    data class Installed(val repaired: Replay.Repaired) : Outcome
    data class Restarted(val restarted: Boolean) : Outcome
    data class ModuleInstalled(val output: String) : Outcome
    data class ConflictsDisabled(val modules: List<Module>) : Outcome
    data class KeyRemoved(val report: KeyRemovalReport) : Outcome

    /** `kind` is the kind of the engine error, such as `restricted`, or `null` for other errors. */
    data class Failed(val text: String, val kind: String?) : Outcome {
        val restricted: Boolean get() = kind == EngineException.RESTRICTED

        companion object {
            fun of(error: Exception): Failed = when (error) {
                is EngineException -> Failed(error.message.orEmpty(), error.kind)
                else -> Failed(error.message ?: error.toString(), null)
            }
        }
    }
}

/** An installed application, for the target list. */
data class InstalledApp(val packageName: String, val label: String, val system: Boolean)

data class UiState(
    val ready: Boolean = false,
    val operation: Operation? = null,
    val privilege: PrivilegeSelection? = null,
    val status: StatusReport? = null,
    /** Why the state of the device could not be read last, while a privilege is available. */
    val statusError: Outcome.Failed? = null,
    val outcome: Outcome? = null,
    val log: List<LogLine> = emptyList(),
    /** Whether the engine log is shown. */
    val logShown: Boolean = false,
    /** A file the user chose, checked and waiting for the user to install it. */
    val candidate: Replay.Candidate? = null,
    /** The installed applications, once loaded, by package. */
    val apps: Map<String, InstalledApp>? = null,
) {
    /** Whether an operation that needs root can be started now. */
    val idle: Boolean get() = ready && operation == null && privilege?.privilege != null
}

class AppViewModel(application: Application) : AndroidViewModel(application) {
    val replay: Replay = (application as ReplayApplication).replay
    val settings: StateFlow<Settings.Values> = replay.settings.values
    val state = MutableStateFlow(UiState())
    private var loadingApps = false

    init {
        RefreshWorker.schedule(application, settings.value, replace = false)
        run(Operation.PREPARING) {
            state.update { it.copy(ready = true) }
            // Shizuku sends its binder once this application comes to the foreground; choosing
            // before it arrives would pass it over for su without asking for its permission.
            if (replay.awaitsShizuku()) replay.shizuku.awaitBinder(SHIZUKU_BINDER_TIMEOUT_MILLIS)
            check(interactive = true)
        }
    }

    /**
     * Runs `block` as `operation`, unless another operation runs. A failure becomes the outcome,
     * with the engine log of the attempt, and the state of the device is read again: an
     * operation that failed half-way may have changed it, and the screen must not show the state
     * from before.
     */
    fun run(operation: Operation, block: suspend () -> Unit) {
        if (state.value.operation != null && operation != Operation.PREPARING) return
        state.update { it.copy(operation = operation, outcome = null) }
        viewModelScope.launch {
            try {
                block()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                val log = (error as? EngineException)?.log.orEmpty()
                state.update { it.copy(outcome = Outcome.Failed.of(error), log = log) }
                // Checking the device and a file change nothing on it, so nothing is read again.
                if (operation !in UNCHANGING) {
                    try {
                        check()
                    } catch (again: CancellationException) {
                        throw again
                    } catch (_: Exception) {
                        // The failure of the operation is what the user is told; a reading
                        // that fails as well must not end the application.
                    }
                }
            } finally {
                state.update { it.copy(operation = null) }
            }
        }
    }

    /**
     * Reads the privilege and the device. With `interactive`, a missing permission is asked for
     * while the user is here; after an operation, no dialog is shown. A failure to read the
     * device is kept apart from the outcome of the operation, which stays as it was, except for
     * a restricted root, which the frame explains with a dialog of its own. The engine log of
     * the failed reading becomes the log, so that the user can read why.
     */
    suspend fun check(interactive: Boolean = false) {
        val selection = replay.selectPrivilege(interactive)
        state.update { it.copy(privilege = selection) }
        val privilege = selection.privilege
        if (privilege == null) {
            state.update { it.copy(status = null, statusError = null) }
            return
        }
        try {
            val status = replay.status(privilege)
            state.update { it.copy(status = status.value, statusError = null) }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            val failure = Outcome.Failed.of(error)
            state.update {
                it.copy(
                    status = null,
                    statusError = failure,
                    outcome = if (failure.restricted) failure else it.outcome,
                    log = (error as? EngineException)?.log ?: it.log,
                )
            }
        }
    }

    fun recheck() = run(Operation.CHECKING) { check(interactive = true) }

    fun grantShizuku() = run(Operation.CHECKING) {
        replay.settings.update { it.copy(permissionDeclined = false) }
        replay.shizuku.requestPermission()
        check()
    }

    /** Ends an operation that the user started: tells its outcome, with its log, and reads the device again. */
    suspend fun finish(outcome: Outcome?, log: List<LogLine>) {
        state.update { it.copy(outcome = outcome ?: it.outcome, log = log) }
        check()
    }

    fun refresh() = run(Operation.REFRESHING) {
        val refreshed = replay.refresh()
        finish(Outcome.Refreshed(refreshed), refreshed.log)
    }

    fun repair() = run(Operation.REPAIRING) {
        val repaired = replay.repair(restart = settings.value.restartOnChange)
        finish(Outcome.Repaired(repaired), repaired.log)
    }

    fun restart() = run(Operation.RESTARTING) {
        val result = replay.restart()
        finish(Outcome.Restarted(result.value), result.log)
    }

    /** The name the provider gives `uri`, or its last path segment. A provider may be slow, so it is asked off the main thread. */
    suspend fun displayName(uri: Uri): String = withContext(Dispatchers.IO) {
        val resolver = getApplication<Application>().contentResolver
        val name = runCatching {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
        }.getOrNull()
        name ?: uri.lastPathSegment.orEmpty()
    }

    fun inspectKeybox(uri: Uri) = run(Operation.INSPECTING) {
        state.update { it.copy(candidate = replay.inspectKeybox(uri, displayName(uri))) }
    }

    fun inspectFingerprint(uri: Uri) = run(Operation.INSPECTING) {
        state.update { it.copy(candidate = replay.inspectFingerprint(uri, displayName(uri))) }
    }

    fun install(candidate: Replay.Candidate) = run(Operation.INSTALLING) {
        state.update { it.copy(candidate = null) }
        val repaired = replay.install(candidate)
        finish(Outcome.Installed(repaired), repaired.log)
    }

    fun dismissCandidate() = state.update { it.copy(candidate = null) }

    fun installModule(component: Component, uri: Uri) = run(Operation.INSTALLING_MODULE) {
        val result = replay.installModule(component, uri)
        finish(Outcome.ModuleInstalled(result.value), result.log)
    }

    fun disableConflicts() = run(Operation.DISABLING_CONFLICTS) {
        val result = replay.disableConflicts()
        finish(Outcome.ConflictsDisabled(result.value), result.log)
    }

    /** Removes an outdated key that the settings keep; the user confirmed losing what was enrolled with it. */
    fun removeKey(key: OutdatedKey) = run(Operation.REMOVING_KEY) {
        val result = replay.removeKey(key)
        finish(Outcome.KeyRemoved(result.value), result.log)
    }

    /** Loads the installed applications once, for the labels of the target list. */
    fun loadApps() {
        if (state.value.apps != null || loadingApps) return
        loadingApps = true
        viewModelScope.launch {
            try {
                val apps = withContext(Dispatchers.IO) {
                    val manager = getApplication<Application>().packageManager
                    runCatching { manager.getInstalledApplications(0) }.getOrDefault(emptyList()).associate { info ->
                        val label = runCatching { manager.getApplicationLabel(info).toString() }.getOrDefault(info.packageName)
                        info.packageName to InstalledApp(info.packageName, label, info.flags and ApplicationInfo.FLAG_SYSTEM != 0)
                    }
                }
                state.update { it.copy(apps = apps) }
            } finally {
                loadingApps = false
            }
        }
    }

    /** Changes the privilege choice and reads the device with it; refused while an operation runs, which would keep the old reading. */
    fun setPrivilegeChoice(choice: PrivilegeChoice) {
        if (state.value.operation != null) return
        replay.settings.update { it.copy(privilege = choice, permissionDeclined = false) }
        recheck()
    }

    fun setBootHook(enabled: Boolean) = run(Operation.CONFIGURING_BOOT) {
        val result = replay.setBootHook(enabled)
        finish(null, result.log)
    }

    fun setWatchPackages(enabled: Boolean) = run(Operation.CONFIGURING_BOOT) {
        val result = replay.setWatchPackages(enabled)
        finish(null, result.log)
    }

    /** Changes settings that touch no system state; the schedule follows them. */
    fun configure(transform: (Settings.Values) -> Settings.Values) {
        val before = settings.value
        replay.settings.update(transform)
        val after = settings.value
        if (before.refreshHours != after.refreshHours || before.refreshUnmetered != after.refreshUnmetered) {
            RefreshWorker.schedule(getApplication(), after, replace = true)
        }
    }

    /** Sets every setting of `protection`; the user can adjust each one afterwards. */
    fun setProtection(protection: Protection) = configure { protection.applyTo(it) }

    /** Sets the spoof flag `key` to `value`, or to its recommended value with `null`. */
    fun setSpoof(key: String, value: Boolean?) = configure { it.copy(spoofOverrides = if (value == null) it.spoofOverrides - key else it.spoofOverrides + (key to value)) }

    fun exclude(packageName: String, excluded: Boolean) = configure {
        it.copy(excludedPackages = if (excluded) (it.excludedPackages + packageName).distinct() else it.excludedPackages - packageName)
    }

    fun resetSources() = configure { it.copy(keyboxSources = Downloader.DEFAULT_KEYBOX_SOURCES, fingerprintUrl = Downloader.DEFAULT_FINGERPRINT_URL) }

    fun dismissOutcome() = state.update { it.copy(outcome = null) }

    fun showLog(shown: Boolean) = state.update { it.copy(logShown = shown) }

    /** Shows `text` as a failure that happened outside an operation. */
    fun fail(text: String) = state.update { it.copy(outcome = Outcome.Failed(text, null)) }

    companion object {
        const val SHIZUKU_BINDER_TIMEOUT_MILLIS = 2_000L

        /** The operations that change nothing on the device. */
        val UNCHANGING = setOf(Operation.PREPARING, Operation.CHECKING, Operation.INSPECTING)
    }
}
