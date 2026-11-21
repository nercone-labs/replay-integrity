package dev.nercone.replayintegrity.ui

import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.EngineException
import dev.nercone.replayintegrity.engine.EngineSettings
import dev.nercone.replayintegrity.engine.StatusReport
import dev.nercone.replayintegrity.engine.TargetScope
import dev.nercone.replayintegrity.privilege.CommandResult
import dev.nercone.replayintegrity.privilege.Privilege
import dev.nercone.replayintegrity.privilege.PrivilegeSelection
import dev.nercone.replayintegrity.privilege.PrivilegeStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The verdict of the home screen must tell every state the device can be in, and never take a
 * failure for a reading that is still in progress; the pending notice must follow the settings
 * the engine applied, whatever the order of their lists.
 */
class ConditionTest {
    object Root : Privilege {
        override val kind = Privilege.Kind.ROOT
        override suspend fun status(): PrivilegeStatus = PrivilegeStatus.Available(0)
        override suspend fun execute(command: List<String>, timeoutMillis: Long): CommandResult = throw UnsupportedOperationException()
    }

    val available = PrivilegeSelection(Root, listOf(Privilege.Kind.ROOT to PrivilegeStatus.Available(0)))
    val missing = PrivilegeSelection(null, listOf(Privilege.Kind.ROOT to PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.DENIED)))
    val applied = Settings.Values(applied = true)

    fun condition(state: UiState, settings: Settings.Values = applied) = HomeScreen.condition(state, settings)

    @Test
    fun beforeTheFirstCheckTheAppIsPreparing() {
        assertEquals(HomeScreen.Condition.PREPARING, condition(UiState(ready = false)))
    }

    @Test
    fun withoutAPrivilegeRootIsNeeded() {
        assertEquals(HomeScreen.Condition.NO_PRIVILEGE, condition(UiState(ready = true, privilege = missing)))
    }

    @Test
    fun aStatusThatFailedIsNotStillBeingChecked() {
        val state = UiState(ready = true, privilege = available, statusError = Outcome.Failed("the engine printed no result", EngineException.OUTPUT))
        assertEquals(HomeScreen.Condition.UNREADABLE, condition(state))
    }

    @Test
    fun aStatusRefusedForRestrictedRootIsRestricted() {
        val state = UiState(ready = true, privilege = available, statusError = Outcome.Failed("missing capabilities", EngineException.RESTRICTED))
        assertEquals(HomeScreen.Condition.RESTRICTED, condition(state))
    }

    @Test
    fun aStatusNotReadYetIsBeingChecked() {
        assertEquals(HomeScreen.Condition.CHECKING, condition(UiState(ready = true, privilege = available)))
    }

    @Test
    fun theStatusDecidesBetweenReadyAttentionAndNotSetUp() {
        val ready = UiState(ready = true, privilege = available, status = StatusReport(strongReady = true))
        val notReady = UiState(ready = true, privilege = available, status = StatusReport(strongReady = false))
        val restricted = UiState(ready = true, privilege = available, status = StatusReport(strongReady = true, missingCapabilities = listOf("CAP_KILL")))
        assertEquals(HomeScreen.Condition.READY, condition(ready))
        assertEquals(HomeScreen.Condition.ATTENTION, condition(notReady))
        assertEquals(HomeScreen.Condition.NOT_SET_UP, condition(notReady, Settings.Values(applied = false)))
        assertEquals(HomeScreen.Condition.RESTRICTED, condition(restricted))
    }

    @Test
    fun changesArePendingOnlyWhenTheAppliedSettingsDiffer() {
        val settings = applied.copy(extraPackages = listOf("a.b", "c.d"))
        val same = UiState(status = StatusReport(settings = settings.engine().copy(extraPackages = listOf("c.d", "a.b"))))
        val other = UiState(status = StatusReport(settings = settings.engine().copy(targetScope = TargetScope.PLAY)))
        assertFalse(Notices.pending(same, settings))
        assertTrue(Notices.pending(other, settings))
        // Nothing is pending before the first apply, or without a reading of the device.
        assertFalse(Notices.pending(other, settings.copy(applied = false)))
        assertFalse(Notices.pending(UiState(), settings))
        assertFalse(Notices.pending(UiState(status = StatusReport(settings = EngineSettings())), Settings.Values()))
    }
}
