package dev.nercone.replayintegrity.privilege

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import kotlin.coroutines.resume
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import rikka.shizuku.Shizuku
import rikka.sui.Sui

/**
 * Runs commands through Shizuku or Sui (which provides the Shizuku interface from a root
 * manager). Commands run in `CommandService`, a user service started by Shizuku, as the user
 * Shizuku runs as: root when Shizuku was started with root, or Sui; shell when it was started
 * through ADB, which cannot act as root.
 */
class ShizukuPrivilege(val context: Context) : Privilege {
    val mutex = Mutex()
    var service: ICommandService? = null

    override val kind: Privilege.Kind
        get() = if (isSui) Privilege.Kind.SUI else Privilege.Kind.SHIZUKU

    val arguments = Shizuku.UserServiceArgs(ComponentName(context.packageName, CommandService::class.java.name))
        .daemon(false)
        .processNameSuffix(PROCESS_SUFFIX)
        .version(SERVICE_VERSION)

    override suspend fun status(): PrivilegeStatus {
        if (!Shizuku.pingBinder()) {
            return PrivilegeStatus.Unavailable(if (isInstalled()) PrivilegeStatus.Reason.NOT_RUNNING else PrivilegeStatus.Reason.NOT_INSTALLED)
        }
        if (Shizuku.isPreV11()) {
            return PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.OUTDATED)
        }
        // Shizuku tells its user when this application attaches, so a Shizuku started through
        // ADB is known before the user is asked for a permission that would not help (-1: unknown yet).
        val attached = Shizuku.getUid()
        if (attached != -1 && attached != Privilege.REQUIRED_UID) return PrivilegeStatus.InsufficientUser(attached)
        if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
            return if (Shizuku.shouldShowRequestPermissionRationale()) {
                PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.DENIED)
            } else {
                PrivilegeStatus.PermissionRequired
            }
        }
        val uid = Shizuku.getUid()
        return if (uid == Privilege.REQUIRED_UID) PrivilegeStatus.Available(uid) else PrivilegeStatus.InsufficientUser(uid)
    }

    /**
     * Asks the user to grant this application access to Shizuku, and returns the status afterwards.
     * The dialog of Shizuku can close without an answer, and Shizuku can stop meanwhile, so the
     * answer is awaited until Shizuku stops, or for `PERMISSION_TIMEOUT_MILLIS` at most.
     */
    override suspend fun requestPermission(): PrivilegeStatus {
        if (!Shizuku.pingBinder()) return status()
        val answered = CompletableDeferred<Unit>()
        val answer = Shizuku.OnRequestPermissionResultListener { requestCode, _ -> if (requestCode == REQUEST_CODE) answered.complete(Unit) }
        val dead = Shizuku.OnBinderDeadListener { answered.complete(Unit) }
        Shizuku.addRequestPermissionResultListener(answer)
        Shizuku.addBinderDeadListener(dead)
        try {
            val asked = try {
                Shizuku.requestPermission(REQUEST_CODE)
                true
            } catch (_: RuntimeException) {
                // Shizuku stopped before it could ask.
                false
            }
            if (asked) withTimeoutOrNull(PERMISSION_TIMEOUT_MILLIS) { answered.await() }
        } finally {
            Shizuku.removeRequestPermissionResultListener(answer)
            Shizuku.removeBinderDeadListener(dead)
        }
        return status()
    }

    /** Waits until the Shizuku binder is received, for example right after boot. */
    suspend fun awaitBinder(timeoutMillis: Long): Boolean = Shizuku.pingBinder() || withTimeoutOrNull(timeoutMillis) {
        suspendCancellableCoroutine { continuation ->
            val listener = object : Shizuku.OnBinderReceivedListener {
                override fun onBinderReceived() {
                    Shizuku.removeBinderReceivedListener(this)
                    if (continuation.isActive) continuation.resume(true)
                }
            }
            Shizuku.addBinderReceivedListenerSticky(listener)
            continuation.invokeOnCancellation { Shizuku.removeBinderReceivedListener(listener) }
        }
    } == true

    override suspend fun execute(command: List<String>, timeoutMillis: Long): CommandResult {
        val service = connect()
        return withContext(Dispatchers.IO) {
            val result = try {
                service.execute(command.toTypedArray(), timeoutMillis)
            } catch (error: Exception) {
                mutex.withLock { this@ShizukuPrivilege.service = null }
                throw PrivilegeException("the Shizuku service failed", error)
            }
            CommandResult(
                result.getInt(CommandService.EXIT_CODE),
                result.getString(CommandService.STDOUT).orEmpty(),
                result.getString(CommandService.STDERR).orEmpty(),
            )
        }
    }

    suspend fun connect(): ICommandService = mutex.withLock {
        service?.takeIf { it.asBinder().pingBinder() }?.let { return it }
        if (status() !is PrivilegeStatus.Available) throw PrivilegeException("Shizuku is not available as root")
        val connected = withTimeoutOrNull(CONNECT_TIMEOUT_MILLIS) {
            suspendCancellableCoroutine<ICommandService> { continuation ->
                val connection = object : ServiceConnection {
                    override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                        if (continuation.isActive) continuation.resume(ICommandService.Stub.asInterface(binder))
                    }

                    override fun onServiceDisconnected(name: ComponentName) {
                        service = null
                    }
                }
                Shizuku.bindUserService(arguments, connection)
            }
        } ?: throw PrivilegeException("the Shizuku service did not start")
        service = connected
        connected
    }

    /** Whether a Shizuku binder may arrive: Sui is present, or the Shizuku application is installed. */
    fun mayStart(): Boolean = isSui || isInstalled()

    fun isInstalled(): Boolean = try {
        context.packageManager.getPackageInfo(SHIZUKU_PACKAGE, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    companion object {
        const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        const val REQUEST_CODE = 1
        const val PROCESS_SUFFIX = "engine"
        const val SERVICE_VERSION = 1
        const val CONNECT_TIMEOUT_MILLIS = 20_000L
        const val PERMISSION_TIMEOUT_MILLIS = 60_000L

        /** Whether Sui provides the Shizuku interface. Set once by `initialize`. */
        var isSui = false

        /** Detects Sui; must run once at application start, before Shizuku is used. */
        fun initialize(context: Context) {
            isSui = Sui.init(context.packageName)
        }
    }
}
