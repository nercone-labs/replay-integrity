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
 * Runs `repair` after a boot, in case the boot hook was not installed (no root manager that runs
 * boot scripts) or Shizuku, which starts after this application, provides the only privilege.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val settings = Settings(context).values.value
        if (!settings.repairAfterBoot || !settings.applied) return
        val request = OneTimeWorkRequestBuilder<RepairWorker>()
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(RepairWorker.NAME, ExistingWorkPolicy.REPLACE, request)
    }
}
