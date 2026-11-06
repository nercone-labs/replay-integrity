package dev.nercone.replayintegrity.privilege

import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** Runs a process and collects its output. Used in the application and in the privileged service alike. */
object ProcessRunner {
    /** The exit code reported when the process did not finish in time and was killed. */
    const val TIMEOUT_EXIT_CODE = -1
    /** The exit code reported when the process could not be started; the error is in stderr. */
    const val START_FAILURE_EXIT_CODE = -2
    const val READER_TIMEOUT_MILLIS = 5_000L

    fun run(command: List<String>, timeoutMillis: Long): CommandResult {
        val process = ProcessBuilder(command).start()
        process.outputStream.close()
        val stdout = AtomicReference("")
        val stderr = AtomicReference("")
        val readers = listOf(
            thread(name = "stdout") { stdout.set(runCatching { process.inputStream.bufferedReader().readText() }.getOrDefault("")) },
            thread(name = "stderr") { stderr.set(runCatching { process.errorStream.bufferedReader().readText() }.getOrDefault("")) },
        )
        val finished = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
        if (!finished) {
            process.destroyForcibly()
            process.waitFor()
        }
        // A process that left a child holding its output open would block the readers forever;
        // they are given a bounded time once the process has ended.
        readers.forEach { it.join(READER_TIMEOUT_MILLIS) }
        return CommandResult(if (finished) process.exitValue() else TIMEOUT_EXIT_CODE, stdout.get(), stderr.get())
    }
}
