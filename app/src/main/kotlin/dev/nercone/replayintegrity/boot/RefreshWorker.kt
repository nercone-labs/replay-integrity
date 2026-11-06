package dev.nercone.replayintegrity.boot

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.ReplayApplication
import dev.nercone.replayintegrity.config.Settings
import java.util.concurrent.TimeUnit

/**
 * Refreshes the keybox and the fingerprint on a schedule, so the verdict never decays: a keybox
 * is replaced before it is revoked or expires, and a fresh Pixel fingerprint replaces one whose
 * build Google has stopped accepting. A failed download is retried with a backoff; the user is
 * notified when a run fails after it was retried.
 */
class RefreshWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val replay = (applicationContext as ReplayApplication).replay
        val settings = replay.settings.values.value
        if (!settings.applied || settings.refreshHours == 0) return Result.success()
        val notifier = Notifier(applicationContext)
        // The work may start the process in the background, before the Shizuku binder arrives.
        if (replay.awaitsShizuku() && replay.selectPrivilege().privilege == null) {
            replay.shizuku.awaitBinder(RepairWorker.BINDER_TIMEOUT_MILLIS)
        }
        val problems = try {
            replay.refresh().problems
        } catch (error: Exception) {
            listOf(error.message ?: error.toString())
        }
        if (problems.isEmpty()) {
            notifier.cancel(Notifier.REFRESH)
            return Result.success()
        }
        if (runAttemptCount < MAX_RETRIES) return Result.retry()
        if (settings.notifyFailures) {
            notifier.notify(Notifier.REFRESH, applicationContext.getString(R.string.app_name), applicationContext.getString(R.string.refresh_failed, problems.joinToString("\n")))
        }
        return Result.success()
    }

    companion object {
        const val NAME = "periodic-refresh"
        const val MAX_RETRIES = 3

        /**
         * Schedules the periodic refresh as `settings` say, or cancels it when they turn it off.
         * With `replace`, a changed interval or network constraint takes effect now; otherwise
         * an existing schedule is kept.
         */
        fun schedule(context: Context, settings: Settings.Values, replace: Boolean) {
            val manager = WorkManager.getInstance(context)
            if (settings.refreshHours <= 0) {
                manager.cancelUniqueWork(NAME)
                return
            }
            val network = if (settings.refreshUnmetered) NetworkType.UNMETERED else NetworkType.CONNECTED
            val request = PeriodicWorkRequestBuilder<RefreshWorker>(settings.refreshHours.toLong(), TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(network).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
                .build()
            manager.enqueueUniquePeriodicWork(NAME, if (replace) ExistingPeriodicWorkPolicy.UPDATE else ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
