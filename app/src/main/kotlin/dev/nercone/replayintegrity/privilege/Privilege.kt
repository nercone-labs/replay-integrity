package dev.nercone.replayintegrity.privilege

/** The output of a finished command. */
data class CommandResult(val exitCode: Int, val stdout: String, val stderr: String)

/** A way to run commands with more privileges than the application has. */
interface Privilege {
    val kind: Kind

    /**
     * Whether commands can be run now, and as which user. A root manager may ask the user to
     * grant access the first time; Shizuku never prompts here (see `requestPermission`).
     */
    suspend fun status(): PrivilegeStatus

    /**
     * Asks the user to grant the access that `status` reported as required, and returns the
     * status afterwards. A root manager asks when `su` runs, so by default this reads the status
     * again; Shizuku asks with a dialog of its own.
     */
    suspend fun requestPermission(): PrivilegeStatus = status()

    /**
     * Runs `command` (no shell is involved) and waits for it, up to `timeoutMillis`.
     * Throws `PrivilegeException` if the privilege is not available.
     */
    suspend fun execute(command: List<String>, timeoutMillis: Long): CommandResult

    enum class Kind { ROOT, SHIZUKU, SUI }

    companion object {
        /** The engine changes system mounts and components, which only the root user may do. */
        const val REQUIRED_UID = 0
        const val SHELL_UID = 2000
    }
}

/** Whether a privilege can be used. */
sealed interface PrivilegeStatus {
    /** Commands run as `uid`, which is `Privilege.REQUIRED_UID`. */
    data class Available(val uid: Int) : PrivilegeStatus

    /** The privilege works, but runs commands as a user that cannot act as root (Shizuku started through ADB). */
    data class InsufficientUser(val uid: Int) : PrivilegeStatus

    /** The user has to grant this application access first. */
    data object PermissionRequired : PrivilegeStatus

    /** The privilege is not installed, not running, or was denied. */
    data class Unavailable(val reason: Reason) : PrivilegeStatus

    enum class Reason { NOT_INSTALLED, NOT_RUNNING, DENIED, OUTDATED }
}

class PrivilegeException(message: String, cause: Throwable? = null) : Exception(message, cause)
