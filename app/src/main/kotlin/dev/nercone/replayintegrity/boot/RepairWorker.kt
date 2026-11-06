package dev.nercone.replayintegrity.boot

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.ReplayApplication

/**
 * Repairs the attestation configuration after a boot: rebuilds the target list, re-applies the
 * spoof flags and the security patch, and removes stale persisted keys, without restarting the
 * Play processes the system has just started (the keystore daemon is restarted only when it may
 * hold a removed key). A privilege that is ready at once (su) is used at once; when Shizuku (or
 * Sui) may provide it, its binder is awaited first, because Shizuku starts after this application.
 */
class RepairWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val replay = (applicationContext as ReplayApplication).replay
        val notifier = Notifier(applicationContext)
        if (replay.awaitsShizuku() && replay.selectPrivilege().privilege == null) {
            replay.shizuku.awaitBinder(BINDER_TIMEOUT_MILLIS)
        }
        return try {
            replay.repair(restart = false)
            notifier.cancel(Notifier.BOOT)
            Result.success()
        } catch (error: Exception) {
            if (replay.settings.values.value.notifyFailures) {
                notifier.notify(Notifier.BOOT, applicationContext.getString(R.string.app_name), applicationContext.getString(R.string.boot_failed, error.message ?: error.toString()))
            }
            Result.failure()
        }
    }

    companion object {
        const val NAME = "repair-after-boot"
        const val BINDER_TIMEOUT_MILLIS = 120_000L
    }
}
