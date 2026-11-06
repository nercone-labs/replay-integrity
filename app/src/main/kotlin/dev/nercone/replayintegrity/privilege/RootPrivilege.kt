package dev.nercone.replayintegrity.privilege

import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Runs commands through `su` (Magisk, KernelSU, APatch and other root managers),
 * as `su -c <command>`. The command is quoted for the shell that `su -c` starts.
 */
class RootPrivilege : Privilege {
    override val kind = Privilege.Kind.ROOT

    override suspend fun status(): PrivilegeStatus = withContext(Dispatchers.IO) {
        val result = try {
            run(listOf("id", "-u"), STATUS_TIMEOUT_MILLIS)
        } catch (_: IOException) {
            return@withContext PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.NOT_INSTALLED)
        }
        val uid = result.stdout.trim().toIntOrNull()
        when {
            result.exitCode == 0 && uid == Privilege.REQUIRED_UID -> PrivilegeStatus.Available(uid)
            result.exitCode == 0 && uid != null -> PrivilegeStatus.InsufficientUser(uid)
            else -> PrivilegeStatus.Unavailable(PrivilegeStatus.Reason.DENIED)
        }
    }

    override suspend fun execute(command: List<String>, timeoutMillis: Long): CommandResult = withContext(Dispatchers.IO) {
        try {
            run(command, timeoutMillis)
        } catch (error: IOException) {
            throw PrivilegeException("su is not available", error)
        }
    }

    fun run(command: List<String>, timeoutMillis: Long): CommandResult =
        ProcessRunner.run(listOf(SU, "-c", command.joinToString(" ") { quote(it) }), timeoutMillis)

    companion object {
        const val SU = "su"
        const val STATUS_TIMEOUT_MILLIS = 15_000L

        /** Quotes `argument` as one word for a POSIX shell. */
        fun quote(argument: String): String = "'" + argument.replace("'", "'\\''") + "'"
    }
}
