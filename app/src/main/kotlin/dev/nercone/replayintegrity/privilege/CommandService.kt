package dev.nercone.replayintegrity.privilege

import android.os.Bundle
import kotlin.system.exitProcess

/**
 * The Shizuku user service: Shizuku (or Sui) starts it in a separate process that runs as the
 * user of Shizuku, from this application's APK, and the application calls it through binder.
 */
class CommandService : ICommandService.Stub() {
    override fun destroy() {
        exitProcess(0)
    }

    override fun execute(command: Array<String>, timeoutMillis: Long): Bundle {
        val result = try {
            ProcessRunner.run(command.toList(), timeoutMillis)
        } catch (error: Exception) {
            CommandResult(ProcessRunner.START_FAILURE_EXIT_CODE, "", error.toString())
        }
        return Bundle().apply {
            putInt(EXIT_CODE, result.exitCode)
            putString(STDOUT, result.stdout)
            putString(STDERR, result.stderr)
        }
    }

    override fun uid(): Int = android.os.Process.myUid()

    companion object {
        const val EXIT_CODE = "exitCode"
        const val STDOUT = "stdout"
        const val STDERR = "stderr"
    }
}
