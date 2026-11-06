package dev.nercone.replayintegrity

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import dev.nercone.replayintegrity.boot.Notifier
import dev.nercone.replayintegrity.privilege.ShizukuPrivilege

class ReplayApplication : Application() {
    lateinit var replay: Replay

    override fun onCreate() {
        super.onCreate()
        ShizukuPrivilege.initialize(this)
        replay = Replay(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(Notifier.CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_DEFAULT),
        )
    }
}
