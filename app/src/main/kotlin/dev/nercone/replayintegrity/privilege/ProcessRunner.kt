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

    /**
     * How long the output is still read after the process ended, for both outputs together. A
     * child of the process (the engine started by `su`) may keep the output open after the
     * process itself ended or was killed, and the caller must not wait for it without end. An
     * output still open then is reported as empty.
     */
    const val DRAIN_MILLIS = 5_000L

    fun run(command: List<String>, timeoutMillis: Long): CommandResult {
        val process = ProcessBuilder(command).start()
        process.outputStream.close()
        val stdout = AtomicReference("")
        val stderr = AtomicReference("")
        // The readers are daemons, so that one still blocked by such a child does not keep the
        // process of the application alive; a failed read leaves the output empty.
        val readers = listOf(
            thread(name = "stdout", isDaemon = true) { stdout.set(runCatching { process.inputStream.bufferedReader().readText() }.getOrDefault("")) },
            thread(name = "stderr", isDaemon = true) { stderr.set(runCatching { process.errorStream.bufferedReader().readText() }.getOrDefault("")) },
        )
        val finished = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
        if (!finished) {
            process.destroyForcibly()
            process.waitFor()
        }
        val deadline = System.nanoTime() + DRAIN_MILLIS * 1_000_000
        readers.forEach { it.join(maxOf(1L, (deadline - System.nanoTime()) / 1_000_000)) }
        return CommandResult(if (finished) process.exitValue() else TIMEOUT_EXIT_CODE, stdout.get(), stderr.get())
    }
}
