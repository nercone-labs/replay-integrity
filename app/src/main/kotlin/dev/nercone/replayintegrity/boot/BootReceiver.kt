package dev.nercone.replayintegrity.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.BackoffPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import dev.nercone.replayintegrity.ReplayApplication
import dev.nercone.replayintegrity.config.Settings
import java.util.concurrent.TimeUnit

/**
 * Repairs after a boot, once the system has started: the boot hook keeps the target list as it
 * is (the package manager does not run that early), may be missing (no root manager that runs
 * boot scripts), or Shizuku, which starts after the boot, provides the only privilege. The
 * periodic refresh is scheduled again too, in case the schedule was lost.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> booted(context)
            Intent.ACTION_MY_PACKAGE_REPLACED -> updated(context)
        }
    }

    fun booted(context: Context) {
        val settings = settingsOf(context)
        RefreshWorker.schedule(context, settings, replace = false)
        if (!settings.repairAfterBoot || !settings.applied) return
        val request = OneTimeWorkRequestBuilder<RepairWorker>()
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .build()
        // A repair that already runs is kept: replacing it would stop it in the middle.
        WorkManager.getInstance(context).enqueueUniqueWork(RepairWorker.NAME, ExistingWorkPolicy.KEEP, request)
    }

    /**
     * The settings of the running application: a receiver runs in its process, after
     * `ReplayApplication.onCreate`, so the one instance that every part writes is read, never a
     * second copy that could miss a write of the first.
     */
    fun settingsOf(context: Context): Settings.Values = (context.applicationContext as ReplayApplication).replay.settings.values.value

    /**
     * After an update of the application, the boot hook still runs the copy of the previous
     * engine in the store, and so does the package watcher, until the hook is installed again.
     * That is done now rather than at the next refresh, which may be hours away or turned off.
     */
    fun updated(context: Context) {
        val settings = settingsOf(context)
        if (!settings.applied) return
        val request = OneTimeWorkRequestBuilder<HookWorker>()
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 1, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(HookWorker.NAME, ExistingWorkPolicy.KEEP, request)
    }
}
