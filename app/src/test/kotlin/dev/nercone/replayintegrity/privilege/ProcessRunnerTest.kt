package dev.nercone.replayintegrity.privilege

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `ProcessRunner` reports the exit code and both outputs of a finished process, reports
 * `TIMEOUT_EXIT_CODE` for a process it had to kill, and never waits for the outputs for longer
 * than `DRAIN_MILLIS` together once the process ended. A POSIX shell (`/bin/sh`) stands in for the engine.
 */
class ProcessRunnerTest {
    fun sh(script: String): List<String> = listOf("/bin/sh", "-c", script)

    @Test
    fun aFinishedProcessGivesItsExitCodeAndBothOutputs() {
        val result = ProcessRunner.run(sh("printf out; printf err >&2; exit 3"), 10_000)
        assertEquals(3, result.exitCode)
        assertEquals("out", result.stdout)
        assertEquals("err", result.stderr)
    }

    @Test
    fun aProcessThatDoesNotFinishInTimeIsKilled() {
        val started = System.nanoTime()
        val result = ProcessRunner.run(sh("exec sleep 30"), 500)
        val elapsed = (System.nanoTime() - started) / 1_000_000
        assertEquals(ProcessRunner.TIMEOUT_EXIT_CODE, result.exitCode)
        assertTrue("waited $elapsed ms", elapsed < 500 + ProcessRunner.DRAIN_MILLIS + 5_000)
    }

    @Test
    fun aChildThatKeepsTheOutputOpenDoesNotHoldTheCallerForEver() {
        // The shell exits soon, but its child inherits both outputs and keeps them open for
        // longer than `DRAIN_MILLIS`. The shell waits a moment first: one that exits at once
        // may leave before the child holds the outputs, and the case would not be reached.
        val started = System.nanoTime()
        val result = ProcessRunner.run(sh("sleep ${ProcessRunner.DRAIN_MILLIS / 1000 + 3} & sleep 0.2; exit 0"), 10_000)
        val elapsed = (System.nanoTime() - started) / 1_000_000
        assertEquals(0, result.exitCode)
        assertTrue("waited $elapsed ms", elapsed < ProcessRunner.DRAIN_MILLIS + 2_000)
    }

    @Test
    fun theStandardInputIsClosed() {
        // A process that reads its input sees its end at once instead of waiting for input.
        val result = ProcessRunner.run(sh("cat; echo done"), 10_000)
        assertEquals(0, result.exitCode)
        assertEquals("done\n", result.stdout)
    }
}
