package dev.nercone.replayintegrity.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import dev.nercone.replayintegrity.config.Settings

/**
 * Repairs after a boot, once the system has started: the boot hook keeps the target list as it
 * is (the package manager does not run that early), may be missing (no root manager that runs
 * boot scripts), or Shizuku, which starts after the boot, provides the only privilege. The
 * periodic refresh is scheduled again too, in case the schedule was lost.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val settings = Settings(context).values.value
        RefreshWorker.schedule(context, settings, replace = false)
        if (!settings.repairAfterBoot || !settings.applied) return
        val request = OneTimeWorkRequestBuilder<RepairWorker>()
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(RepairWorker.NAME, ExistingWorkPolicy.REPLACE, request)
    }
}
