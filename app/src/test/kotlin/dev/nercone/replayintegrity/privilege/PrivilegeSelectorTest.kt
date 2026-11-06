package dev.nercone.replayintegrity.privilege

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The selection decides with which privilege the engine runs. Automatic must not give Shizuku
 * up merely because its permission has not been granted yet: with the user present, it asks
 * for the permission before it falls back to `su`.
 */
class PrivilegeSelectorTest {
    class FakePrivilege(
        override val kind: Privilege.Kind,
        var status: PrivilegeStatus,
        val statusAfterRequest: PrivilegeStatus = status,
    ) : Privilege {
        var statusReads = 0
        var requests = 0

        override suspend fun status(): PrivilegeStatus {
            statusReads++
            return status
        }

        override suspend fun requestPermission(): PrivilegeStatus {
            requests++
            status = statusAfterRequest
            return status
        }

        override suspend fun execute(command: List<String>, timeoutMillis: Long): CommandResult =
            throw UnsupportedOperationException("the test only selects privileges")
    }

    fun shizukuPrivilege(status: PrivilegeStatus, afterRequest: PrivilegeStatus = status) = FakePrivilege(Privilege.Kind.SHIZUKU, status, afterRequest)
    fun rootPrivilege(status: PrivilegeStatus) = FakePrivilege(Privilege.Kind.ROOT, status)

    fun select(selector: PrivilegeSelector, choice: PrivilegeChoice, interactive: Boolean = false): PrivilegeSelection =
        runBlocking { selector.select(choice, interactive) }

    @Test
    fun automaticUsesShizukuWithoutAskingWhenItIsAvailable() {
        val shizuku = shizukuPrivilege(PrivilegeStatus.Available(0))
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.AUTOMATIC, interactive = true)
        assertEquals(shizuku, selection.privilege)
        assertEquals(0, shizuku.requests)
        assertEquals("su is not asked when Shizuku can run", 0, root.statusReads)
        assertEquals(listOf(Privilege.Kind.SHIZUKU to PrivilegeStatus.Available(0)), selection.statuses)
    }

    @Test
    fun automaticAsksForShizukuBeforeItFallsBackToSu() {
        val shizuku = shizukuPrivilege(PrivilegeStatus.PermissionRequired, PrivilegeStatus.Available(0))
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.AUTOMATIC, interactive = true)
        assertEquals(shizuku, selection.privilege)
        assertEquals(1, shizuku.requests)
        assertEquals("su is not asked once Shizuku is granted", 0, root.statusReads)
        assertEquals(listOf(Privilege.Kind.SHIZUKU to PrivilegeStatus.Available(0)), selection.statuses)
    }

    @Test
    fun automaticFallsBackToSuWhenShizukuIsDenied() {
        val shizuku = shizukuPrivilege(PrivilegeStatus.PermissionRequired, PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.DENIED))
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.AUTOMATIC, interactive = true)
        assertEquals(root, selection.privilege)
        assertEquals(1, shizuku.requests)
        assertEquals(1, root.statusReads)
        assertEquals(
            listOf(
                Privilege.Kind.SHIZUKU to PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.DENIED),
                Privilege.Kind.ROOT to PrivilegeStatus.Available(0),
            ),
            selection.statuses,
        )
    }

    @Test
    fun automaticDoesNotAskWithoutTheUser() {
        val shizuku = shizukuPrivilege(PrivilegeStatus.PermissionRequired, PrivilegeStatus.Available(0))
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.AUTOMATIC)
        assertEquals("a boot worker must not open a permission dialog", 0, shizuku.requests)
        assertEquals(1, root.statusReads)
        assertEquals(root, selection.privilege)
    }

    @Test
    fun automaticFallsBackToSuWhenShizukuRunsAsAnotherUser() {
        val shell = PrivilegeStatus.InsufficientUser(Privilege.SHELL_UID)
        val shizuku = shizukuPrivilege(PrivilegeStatus.PermissionRequired, shell)
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.AUTOMATIC, interactive = true)
        assertEquals("Shizuku started through ADB cannot write /data/adb", root, selection.privilege)
        assertEquals(1, shizuku.requests)
        assertEquals(
            listOf(
                Privilege.Kind.SHIZUKU to shell,
                Privilege.Kind.ROOT to PrivilegeStatus.Available(0),
            ),
            selection.statuses,
        )
    }

    @Test
    fun automaticDoesNotAskWhenShizukuCannotRun() {
        val shizuku = shizukuPrivilege(PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.NOT_RUNNING), PrivilegeStatus.Available(0))
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.AUTOMATIC, interactive = true)
        assertEquals(0, shizuku.requests)
        assertEquals(root, selection.privilege)
    }

    @Test
    fun shizukuOnlyAsksForPermission() {
        val granted = shizukuPrivilege(PrivilegeStatus.PermissionRequired, PrivilegeStatus.Available(0))
        val grantedSelection = select(PrivilegeSelector(granted, rootPrivilege(PrivilegeStatus.Available(0))), PrivilegeChoice.SHIZUKU, interactive = true)
        assertEquals(granted, grantedSelection.privilege)
        assertEquals(1, granted.requests)

        val denied = shizukuPrivilege(PrivilegeStatus.PermissionRequired, PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.DENIED))
        val deniedSelection = select(PrivilegeSelector(denied, rootPrivilege(PrivilegeStatus.Available(0))), PrivilegeChoice.SHIZUKU, interactive = true)
        assertNull("su is never used in Shizuku-only mode", deniedSelection.privilege)
        assertEquals(1, denied.requests)
    }

    @Test
    fun automaticFallsBackToSuWhenShizukuIsDeclinedOnce() {
        // Shizuku keeps no refusal of a single request: the permission stays to be asked for.
        val shizuku = shizukuPrivilege(PrivilegeStatus.PermissionRequired)
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.AUTOMATIC, interactive = true)
        assertEquals(root, selection.privilege)
        assertEquals(1, shizuku.requests)
        assertTrue("the refusal is reported, so that it is not asked for again", selection.declined)
        assertEquals(
            listOf(
                Privilege.Kind.SHIZUKU to PrivilegeStatus.PermissionRequired,
                Privilege.Kind.ROOT to PrivilegeStatus.Available(0),
            ),
            selection.statuses,
        )
    }

    @Test
    fun selectionIsNotDeclinedWithoutARefusal() {
        fun declined(shizuku: FakePrivilege, interactive: Boolean) =
            select(PrivilegeSelector(shizuku, rootPrivilege(PrivilegeStatus.Available(0))), PrivilegeChoice.AUTOMATIC, interactive).declined
        assertFalse("granted", declined(shizukuPrivilege(PrivilegeStatus.PermissionRequired, PrivilegeStatus.Available(0)), interactive = true))
        assertFalse("already available", declined(shizukuPrivilege(PrivilegeStatus.Available(0)), interactive = true))
        assertFalse("not running", declined(shizukuPrivilege(PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.NOT_RUNNING)), interactive = true))
        assertFalse("not asked", declined(shizukuPrivilege(PrivilegeStatus.PermissionRequired), interactive = false))
    }

    @Test
    fun automaticDoesNotAskShizukuThatRunsAsAnotherUser() {
        val shell = PrivilegeStatus.InsufficientUser(Privilege.SHELL_UID)
        val shizuku = shizukuPrivilege(shell, PrivilegeStatus.Available(0))
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.AUTOMATIC, interactive = true)
        assertEquals("a permission for Shizuku started through ADB would not help", 0, shizuku.requests)
        assertEquals(root, selection.privilege)
        assertEquals(listOf(Privilege.Kind.SHIZUKU to shell, Privilege.Kind.ROOT to PrivilegeStatus.Available(0)), selection.statuses)
    }

    @Test
    fun shizukuOnlyReportsADeclinedPermission() {
        val shizuku = shizukuPrivilege(PrivilegeStatus.PermissionRequired)
        val selection = select(PrivilegeSelector(shizuku, rootPrivilege(PrivilegeStatus.Available(0))), PrivilegeChoice.SHIZUKU, interactive = true)
        assertNull(selection.privilege)
        assertTrue(selection.declined)
        assertEquals(listOf(Privilege.Kind.SHIZUKU to PrivilegeStatus.PermissionRequired), selection.statuses)
    }

    @Test
    fun rootOnlyDoesNotTouchShizuku() {
        val shizuku = shizukuPrivilege(PrivilegeStatus.PermissionRequired, PrivilegeStatus.Available(0))
        val root = rootPrivilege(PrivilegeStatus.Available(0))
        val selection = select(PrivilegeSelector(shizuku, root), PrivilegeChoice.ROOT, interactive = true)
        assertEquals(root, selection.privilege)
        assertEquals(0, shizuku.statusReads)
        assertEquals(0, shizuku.requests)
        assertEquals(listOf(Privilege.Kind.ROOT to PrivilegeStatus.Available(0)), selection.statuses)
    }
}
