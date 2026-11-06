package dev.nercone.replayintegrity.boot

import android.Manifest
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import dev.nercone.replayintegrity.R
import dev.nercone.replayintegrity.ui.MainActivity

/** Tells the user about a problem found without them: after a boot, or in a scheduled refresh. */
class Notifier(val context: Context) {
    /** Posts `text` under `id`, replacing an earlier notification of the same id. Without the permission, nothing is shown. */
    fun notify(id: Int, title: String, text: String) {
        if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val intent = PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(intent)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(context).notify(id, notification)
    }

    fun cancel(id: Int) = NotificationManagerCompat.from(context).cancel(id)

    companion object {
        const val CHANNEL = "status"
        const val BOOT = 1
        const val REFRESH = 2
    }
}
