package dev.nercone.replayintegrity.privilege

import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Runs a process and collects its output. Used in the application and in the privileged service alike. */
object ProcessRunner {
    /** The exit code reported when the process did not finish in time and was killed. */
    const val TIMEOUT_EXIT_CODE = -1

    fun run(command: List<String>, timeoutMillis: Long): CommandResult {
        val process = ProcessBuilder(command).start()
        process.outputStream.close()
        var stdout = ""
        var stderr = ""
        val readers = listOf(
            thread(name = "stdout") { stdout = process.inputStream.bufferedReader().readText() },
            thread(name = "stderr") { stderr = process.errorStream.bufferedReader().readText() },
        )
        val finished = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
        if (!finished) {
            process.destroyForcibly()
            process.waitFor()
        }
        readers.forEach { it.join() }
        return CommandResult(if (finished) process.exitValue() else TIMEOUT_EXIT_CODE, stdout, stderr)
    }
}
