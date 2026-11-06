package dev.nercone.replayintegrity

import android.content.Context
import dev.nercone.replayintegrity.config.Settings
import dev.nercone.replayintegrity.engine.ApplyReport
import dev.nercone.replayintegrity.engine.BootHook
import dev.nercone.replayintegrity.engine.Component
import dev.nercone.replayintegrity.engine.Engine
import dev.nercone.replayintegrity.engine.InstallReport
import dev.nercone.replayintegrity.engine.StatusReport
import dev.nercone.replayintegrity.net.Downloader
import dev.nercone.replayintegrity.net.Fetched
import dev.nercone.replayintegrity.privilege.Privilege
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import dev.nercone.replayintegrity.privilege.PrivilegeException
import dev.nercone.replayintegrity.privilege.PrivilegeSelection
import dev.nercone.replayintegrity.privilege.PrivilegeSelector
import dev.nercone.replayintegrity.privilege.RootPrivilege
import dev.nercone.replayintegrity.privilege.ShizukuPrivilege
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The application: the engine, the settings, the privileges and the downloader, with the
 * operations the user interface and the boot worker share. Operations that change the system are
 * serialized, so a manual refresh and the boot worker never run the engine at once.
 */
class Replay(val context: Context) {
    val engine = Engine(context)
    val settings = Settings(context)
    val shizuku = ShizukuPrivilege(context)
    val selector = PrivilegeSelector(shizuku, RootPrivilege())
    val downloader = Downloader()
    val operations = Mutex()

    /** What a full refresh did, for the user interface and the notification. */
    data class Refreshed(val keybox: InstallReport?, val fingerprint: InstallReport?, val apply: ApplyReport, val warnings: List<String>)

    /**
     * Chooses the privilege. With [interactive], a missing permission is asked for while the user
     * is present, once: Shizuku keeps no refusal, so a declined permission is remembered and not
     * asked for again until the privilege choice changes.
     */
    suspend fun selectPrivilege(interactive: Boolean = false): PrivilegeSelection {
        val values = settings.values.value
        val selection = selector.select(values.privilege, interactive && !values.permissionDeclined)
        if (selection.declined) settings.update { it.copy(permissionDeclined = true) }
        return selection
    }

    fun awaitsShizuku(): Boolean = settings.values.value.privilege != PrivilegeChoice.ROOT && shizuku.mayStart()

    suspend fun privilege(): Privilege = selectPrivilege().privilege ?: throw PrivilegeException("no privilege can run the engine as root")

    /** Writes the settings to a cache file for the engine's `--settings`. */
    suspend fun settingsFile(): File = engine.writeCache("settings.json", settings.toEngineJson())

    /** Downloads and caches the certificate status list, or `null` if it cannot be fetched. */
    suspend fun statusListFile(): File? = runCatching { write("status.json", downloader.statusList()) }.getOrNull()

    suspend fun write(name: String, fetched: Fetched): File = withContext(Dispatchers.IO) {
        File(context.cacheDir, name).apply { writeBytes(fetched.bytes) }
    }

    suspend fun status(): StatusReport = engine.status(privilege(), statusListFile()).value

    /**
     * Downloads the keybox (unless the user keeps their own), the fingerprint (likewise) and the
     * status list, installs what was fetched, then applies the configuration. A download failure
     * is a warning, not an error: the existing files stay and the apply still runs, so a bad
     * network never leaves the device worse off. Returns what was done.
     */
    suspend fun refresh(restart: Boolean = true): Refreshed = operations.withLock {
        val privilege = privilege()
        val warnings = mutableListOf<String>()
        val status = statusListFile()
        val values = settings.values.value
        val keybox = if (values.autoKeybox) {
            runCatching {
                val fetched = downloader.keybox()
                engine.installKeybox(privilege, write("keybox.xml", fetched), fetched.source, status).value
            }.getOrElse { warnings += "keybox: ${it.message}"; null }
        } else {
            null
        }
        val settingsFile = settingsFile()
        val fingerprint = if (values.autoFingerprint) {
            runCatching {
                val fetched = downloader.fingerprint()
                engine.installFingerprint(privilege, write("fingerprint.prop", fetched), fetched.source, settingsFile).value
            }.getOrElse { warnings += "fingerprint: ${it.message}"; null }
        } else {
            null
        }
        // Restarting the keystore ends the Play services and Play Store processes, which is
        // disruptive, so it is done only when there is a reason: an input changed, this is the
        // first apply, or the caller forced it. A periodic run on an unchanged device (or one
        // whose downloads just failed) then re-applies the configuration without the disruption.
        val changed = keybox?.changed == true || fingerprint?.changed == true
        val firstApply = !settings.values.value.applied
        val apply = engine.apply(privilege, settingsFile, restart && (changed || firstApply)).value
        settings.update { it.copy(applied = true) }
        synchronizeHook(privilege, warnings)
        Refreshed(keybox, fingerprint, apply, warnings)
    }

    /**
     * Re-applies the configuration without downloading anything: rebuild the target list,
     * re-apply the spoof flags and the security patch, remove the stale persisted keys that keep
     * an application on an old keybox, and restart the keystore. This is what the boot hook runs.
     */
    suspend fun repair(restart: Boolean = true): ApplyReport = operations.withLock {
        engine.apply(privilege(), settingsFile(), restart).value
    }

    suspend fun restart(): Boolean = operations.withLock { engine.restart(privilege()).value.restarted }

    suspend fun installModule(component: Component, zip: File): String = operations.withLock {
        engine.installModule(privilege(), component, zip).value.output
    }

    /** Installs or removes the boot hook as the settings say; a failure is a warning. */
    suspend fun synchronizeHook(privilege: Privilege, warnings: MutableList<String>) {
        runCatching {
            if (settings.values.value.bootHook) engine.installHook(privilege).value else engine.removeHook(privilege).value
        }.onFailure { warnings += "boot hook: ${it.message}" }
    }

    suspend fun setBootHook(enabled: Boolean): BootHook = operations.withLock {
        settings.update { it.copy(bootHook = enabled) }
        val privilege = privilege()
        if (enabled) engine.installHook(privilege).value else engine.removeHook(privilege).value
    }
}
