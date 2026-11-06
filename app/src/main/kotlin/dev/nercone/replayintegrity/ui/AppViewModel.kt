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
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.EngineException
import dev.nercone.replayintegrity.engine.LogLine
import dev.nercone.replayintegrity.engine.Module
import dev.nercone.replayintegrity.engine.StatusReport
import dev.nercone.replayintegrity.engine.TargetMode
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
enum class Operation { PREPARING, CHECKING, REFRESHING, REPAIRING, RESTARTING, INSPECTING, INSTALLING, INSTALLING_MODULE, CONFIGURING_BOOT, DISABLING_CONFLICTS }

/** What the user is told about the last operation. */
sealed interface Outcome {
    data class Refreshed(val refreshed: Replay.Refreshed) : Outcome
    data class Repaired(val repaired: Replay.Repaired) : Outcome
    data class Installed(val repaired: Replay.Repaired) : Outcome
    data class Restarted(val restarted: Boolean) : Outcome
    data class ModuleInstalled(val output: String) : Outcome
    data class ConflictsDisabled(val modules: List<Module>) : Outcome

    /** `kind` is the kind of the engine error, such as `restricted`, or `null` for other errors. */
    data class Failed(val text: String, val kind: String?) : Outcome {
        val restricted: Boolean get() = kind == EngineException.RESTRICTED
    }
}

/** An installed application, for the target list. */
data class InstalledApp(val packageName: String, val label: String, val system: Boolean)

data class UiState(
    val ready: Boolean = false,
    val operation: Operation? = null,
    val privilege: PrivilegeSelection? = null,
    val status: StatusReport? = null,
    val outcome: Outcome? = null,
    val log: List<LogLine> = emptyList(),
    /** A file the user chose, checked and waiting for the user to install it. */
    val candidate: Replay.Candidate? = null,
    /** The installed applications, once loaded, by package. */
    val apps: Map<String, InstalledApp>? = null,
)

class AppViewModel(application: Application) : AndroidViewModel(application) {
    val replay: Replay = (application as ReplayApplication).replay
    val settings: StateFlow<Settings.Values> = replay.settings.values
    val state = MutableStateFlow(UiState())

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

    /** Runs `block` as `operation`, unless another operation runs; failures become the outcome. */
    fun run(operation: Operation, block: suspend () -> Unit) {
        if (state.value.operation != null && operation != Operation.PREPARING) return
        state.update { it.copy(operation = operation, outcome = null) }
        viewModelScope.launch {
            try {
                block()
            } catch (error: CancellationException) {
                throw error
            } catch (error: EngineException) {
                state.update { it.copy(outcome = Outcome.Failed(error.message.orEmpty(), error.kind), log = error.log) }
            } catch (error: Exception) {
                state.update { it.copy(outcome = Outcome.Failed(error.message ?: error.toString(), null)) }
            } finally {
                state.update { it.copy(operation = null) }
            }
        }
    }

    /**
     * Reads the privilege and the device. With `interactive`, a missing permission is asked for
     * while the user is here; after an operation, no dialog is shown.
     */
    suspend fun check(interactive: Boolean = false) {
        val selection = replay.selectPrivilege(interactive)
        state.update { it.copy(privilege = selection) }
        if (selection.privilege == null) {
            state.update { it.copy(status = null) }
            return
        }
        val status = replay.status()
        state.update { it.copy(status = status.value) }
    }

    fun recheck() = run(Operation.CHECKING) { check(interactive = true) }

    fun grantShizuku() = run(Operation.CHECKING) {
        replay.settings.update { it.copy(permissionDeclined = false) }
        replay.shizuku.requestPermission()
        check()
    }

    fun refresh() = run(Operation.REFRESHING) {
        val refreshed = replay.refresh()
        state.update { it.copy(outcome = Outcome.Refreshed(refreshed), log = refreshed.log) }
        check()
    }

    fun repair() = run(Operation.REPAIRING) {
        val repaired = replay.repair(restart = settings.value.restartOnChange)
        state.update { it.copy(outcome = Outcome.Repaired(repaired), log = repaired.log) }
        check()
    }

    fun restart() = run(Operation.RESTARTING) {
        val result = replay.restart()
        state.update { it.copy(outcome = Outcome.Restarted(result.value), log = result.log) }
        check()
    }

    /** The name the provider gives `uri`, or its last path segment. */
    fun displayName(uri: Uri): String {
        val resolver = getApplication<Application>().contentResolver
        val name = runCatching {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
        }.getOrNull()
        return name ?: uri.lastPathSegment.orEmpty()
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
        state.update { it.copy(outcome = Outcome.Installed(repaired), log = repaired.log) }
        check()
    }

    fun dismissCandidate() = state.update { it.copy(candidate = null) }

    fun installModule(component: Component, uri: Uri) = run(Operation.INSTALLING_MODULE) {
        val result = replay.installModule(component, uri)
        state.update { it.copy(outcome = Outcome.ModuleInstalled(result.value), log = result.log) }
        check()
    }

    fun disableConflicts() = run(Operation.DISABLING_CONFLICTS) {
        val result = replay.disableConflicts()
        state.update { it.copy(outcome = Outcome.ConflictsDisabled(result.value), log = result.log) }
        check()
    }

    /** Loads the installed applications once, for the labels of the target list. */
    fun loadApps() {
        if (state.value.apps != null) return
        viewModelScope.launch {
            val apps = withContext(Dispatchers.IO) {
                val manager = getApplication<Application>().packageManager
                runCatching { manager.getInstalledApplications(0) }.getOrDefault(emptyList()).associate { info ->
                    val label = runCatching { manager.getApplicationLabel(info).toString() }.getOrDefault(info.packageName)
                    info.packageName to InstalledApp(info.packageName, label, info.flags and ApplicationInfo.FLAG_SYSTEM != 0)
                }
            }
            state.update { it.copy(apps = apps) }
        }
    }

    fun setPrivilegeChoice(choice: PrivilegeChoice) {
        replay.settings.update { it.copy(privilege = choice, permissionDeclined = false) }
        recheck()
    }

    fun setBootHook(enabled: Boolean) = run(Operation.CONFIGURING_BOOT) {
        val result = replay.setBootHook(enabled)
        state.update { it.copy(log = result.log) }
        check()
    }

    fun setWatchPackages(enabled: Boolean) = run(Operation.CONFIGURING_BOOT) {
        val result = replay.setWatchPackages(enabled)
        state.update { it.copy(log = result.log) }
        check()
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

    fun setTargetMode(mode: TargetMode) = configure { it.copy(targetMode = mode) }

    /** Sets the spoof flag `key` to `value`, or to its recommended value with `null`. */
    fun setSpoof(key: String, value: Boolean?) = configure { it.copy(spoofOverrides = if (value == null) it.spoofOverrides - key else it.spoofOverrides + (key to value)) }

    fun exclude(packageName: String, excluded: Boolean) = configure {
        it.copy(excludedPackages = if (excluded) (it.excludedPackages + packageName).distinct() else it.excludedPackages - packageName)
    }

    fun resetSources() = configure { it.copy(keyboxUrl = Downloader.DEFAULT_KEYBOX_URL, fingerprintUrl = Downloader.DEFAULT_FINGERPRINT_URL) }

    fun dismissOutcome() = state.update { it.copy(outcome = null) }

    companion object {
        const val SHIZUKU_BINDER_TIMEOUT_MILLIS = 2_000L
    }
}
