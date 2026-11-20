package dev.nercone.replayintegrity.boot

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dev.nercone.replayintegrity.ReplayApplication
import kotlinx.coroutines.CancellationException

/**
 * Installs the boot hook again after an update of the application, so that the hook and the
 * package watcher run the engine of this version (`Replay.updateHook`). Nothing else changes:
 * no download, no apply, no restart. A failure (Shizuku has not started yet after the update,
 * say) is retried a few times with a backoff, and not notified, because nothing is worse than
 * before the update; the next refresh installs the hook again in any case.
 */
class HookWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val replay = (applicationContext as ReplayApplication).replay
        if (replay.awaitsShizuku() && replay.selectPrivilege().privilege == null) {
            replay.shizuku.awaitBinder(RepairWorker.BINDER_TIMEOUT_MILLIS)
        }
        return try {
            replay.updateHook()
            Result.success()
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            if (runAttemptCount < MAX_RETRIES) Result.retry() else Result.failure()
        }
    }

    companion object {
        const val NAME = "hook-after-update"
        const val MAX_RETRIES = 3
    }
}
