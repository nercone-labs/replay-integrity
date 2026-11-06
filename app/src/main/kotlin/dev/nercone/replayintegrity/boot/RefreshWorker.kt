package dev.nercone.replayintegrity.boot

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dev.nercone.replayintegrity.ReplayApplication
import java.util.concurrent.TimeUnit

/**
 * Refreshes the keybox and the fingerprint on a schedule, so the verdict never decays: a keybox
 * is replaced before it is revoked or expires, and a fresh Pixel fingerprint replaces one whose
 * build Google has stopped accepting. It needs the network; without it, the run is retried.
 */
class RefreshWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val replay = (applicationContext as ReplayApplication).replay
        if (!replay.settings.values.value.applied) return Result.success()
        return try {
            val refreshed = replay.refresh()
            if (refreshed.warnings.isEmpty()) Result.success() else Result.retry()
        } catch (_: Exception) {
            Result.retry()
        }
    }

    companion object {
        const val NAME = "periodic-refresh"
        const val INTERVAL_HOURS = 6L

        /** Schedules the periodic refresh, keeping an existing schedule. */
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<RefreshWorker>(INTERVAL_HOURS, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
