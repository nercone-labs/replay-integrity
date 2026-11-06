package dev.nercone.replayintegrity.boot

import android.Manifest
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.ReplayApplication
import dev.nercone.replayintegrity.ui.MainActivity

/**
 * Repairs the attestation configuration after a boot: it removes stale persisted keys, re-applies
 * the spoof flags and the security patch, and restarts the keystore. A privilege that is ready at
 * once (su) is used at once; when only Shizuku (or Sui) can be used, its binder is awaited first,
 * because Shizuku starts after this application.
 */
class RepairWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val replay = (applicationContext as ReplayApplication).replay
        if (replay.awaitsShizuku() && replay.selectPrivilege().privilege == null) {
            replay.shizuku.awaitBinder(BINDER_TIMEOUT_MILLIS)
        }
        return try {
            replay.repair()
            Result.success()
        } catch (error: Exception) {
            notify(applicationContext.getString(R.string.boot_failed, error.message ?: error.toString()))
            Result.failure()
        }
    }

    fun notify(text: String) {
        if (applicationContext.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val intent = PendingIntent.getActivity(applicationContext, 0, Intent(applicationContext, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(applicationContext, ReplayApplication.CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(applicationContext.getString(R.string.app_name))
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(intent)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(applicationContext).notify(NOTIFICATION_ID, notification)
    }

    companion object {
        const val NAME = "repair-after-boot"
        const val NOTIFICATION_ID = 1
        const val BINDER_TIMEOUT_MILLIS = 120_000L
    }
}
