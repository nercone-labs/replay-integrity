package dev.nercone.replayintegrity.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.nercone.replayintegrity.Replay
import dev.nercone.replayintegrity.ReplayApplication
import dev.nercone.replayintegrity.boot.RefreshWorker
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.EngineException
import dev.nercone.replayintegrity.engine.StatusReport
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** What the engine is doing now, shown as a progress subtitle. */
enum class Operation { CHECKING, REFRESHING, REPAIRING, RESTARTING }

/** The outcome of the last operation, shown to the user. */
sealed interface Outcome {
    data class Refreshed(val warnings: List<String>) : Outcome
    data class Failed(val text: String) : Outcome
    data object Done : Outcome
}

/** The state the user interface renders. */
data class UiState(
    val status: StatusReport? = null,
    val operation: Operation? = null,
    val outcome: Outcome? = null,
)

class AppViewModel(application: Application) : AndroidViewModel(application) {
    val replay: Replay = (application as ReplayApplication).replay

    private val mutableState = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = mutableState.asStateFlow()
    val settings: StateFlow<Settings.Values> = replay.settings.values

    init {
        RefreshWorker.schedule(application)
        refresh()
    }

    /** Reads the current status, without changing anything. */
    fun refresh() = run(Operation.CHECKING) {
        val status = replay.status()
        mutableState.value = mutableState.value.copy(status = status, outcome = Outcome.Done)
    }

    /** Downloads and installs the keybox and fingerprint, then applies and restarts. */
    fun refreshNow() = run(Operation.REFRESHING) {
        val refreshed = replay.refresh()
        val status = replay.status()
        mutableState.value = mutableState.value.copy(status = status, outcome = Outcome.Refreshed(refreshed.warnings))
    }

    /** Re-applies the configuration and removes stale keys, without downloading. */
    fun repair() = run(Operation.REPAIRING) {
        replay.repair()
        val status = replay.status()
        mutableState.value = mutableState.value.copy(status = status, outcome = Outcome.Done)
    }

    fun setPrivilege(choice: PrivilegeChoice) {
        replay.settings.update { it.copy(privilege = choice, permissionDeclined = false) }
        refresh()
    }

    fun setAutoKeybox(enabled: Boolean) = replay.settings.update { it.copy(autoKeybox = enabled) }

    fun setAutoFingerprint(enabled: Boolean) = replay.settings.update { it.copy(autoFingerprint = enabled) }

    fun setBootHook(enabled: Boolean) = run(Operation.REPAIRING) {
        replay.setBootHook(enabled)
        val status = replay.status()
        mutableState.value = mutableState.value.copy(status = status, outcome = Outcome.Done)
    }

    fun dismissOutcome() {
        mutableState.value = mutableState.value.copy(outcome = null)
    }

    private fun run(operation: Operation, block: suspend () -> Unit) {
        if (mutableState.value.operation != null) return
        mutableState.value = mutableState.value.copy(operation = operation, outcome = null)
        viewModelScope.launch {
            try {
                block()
            } catch (error: EngineException) {
                mutableState.value = mutableState.value.copy(outcome = Outcome.Failed(error.message ?: error.toString()))
            } catch (error: Exception) {
                mutableState.value = mutableState.value.copy(outcome = Outcome.Failed(error.message ?: error.toString()))
            } finally {
                mutableState.value = mutableState.value.copy(operation = null)
            }
        }
    }
}
