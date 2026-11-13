package com.selfcheck.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import java.util.concurrent.TimeUnit

/** 백그라운드에서 점검을 돌립니다. 화면을 꺼도 계속 진행됩니다. */
class ScanWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {

    companion object {
        const val TAG = "scan"
        private const val CHANNEL = "scan"
        private const val NOTI_PROGRESS = 1
        private const val NOTI_DONE = 2

        private val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        fun runNow(ctx: Context) {
            val req = OneTimeWorkRequestBuilder<ScanWorker>().addTag(TAG).setConstraints(constraints).build()
            WorkManager.getInstance(ctx).enqueueUniqueWork("scan-now", ExistingWorkPolicy.KEEP, req)
        }

        fun schedule(ctx: Context, enabled: Boolean) {
            val wm = WorkManager.getInstance(ctx)
            if (!enabled) { wm.cancelUniqueWork("scan-daily"); return }
            val req = PeriodicWorkRequestBuilder<ScanWorker>(24, TimeUnit.HOURS)
                .addTag(TAG).setConstraints(constraints).setInitialDelay(24, TimeUnit.HOURS).build()
            wm.enqueueUniquePeriodicWork("scan-daily", ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun cancel(ctx: Context) = WorkManager.getInstance(ctx).cancelUniqueWork("scan-now")

        fun ensureChannel(ctx: Context) {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "점검 진행", NotificationManager.IMPORTANCE_LOW))
        }
    }

    private fun notification(text: String, ongoing: Boolean, done: Int = 0, total: Int = 0): android.app.Notification {
        ensureChannel(applicationContext)
        val open = PendingIntent.getActivity(
            applicationContext, 0, Intent(applicationContext, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return android.app.Notification.Builder(applicationContext, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentTitle("셀프 점검")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(ongoing)
            .setAutoCancel(!ongoing)
            .apply { if (total > 0) setProgress(total, done, false) }
            .build()
    }

    private fun foreground(text: String, done: Int = 0, total: Int = 0) {
        val n = notification(text, true, done, total)
        val info = if (Build.VERSION.SDK_INT >= 29)
            ForegroundInfo(NOTI_PROGRESS, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        else ForegroundInfo(NOTI_PROGRESS, n)
        runCatching { setForegroundAsync(info).get() }
    }

    private fun report(stage: String, done: Int = 0, total: Int = 0) {
        setProgressAsync(workDataOf("stage" to stage, "done" to done, "total" to total))
    }

    override fun doWork(): Result {
        val ctx = applicationContext
        val names = Store.usernames(ctx)
        if (names.isEmpty()) return Result.success()

        foreground("점검 준비 중")
        report("준비 중")

        val hasRefs = !FaceMatcher.refsDir(ctx).listFiles().isNullOrEmpty()
        val matcher = if (hasRefs) runCatching {
            FaceMatcher(ctx) { report(it) }.also { it.loadRefs(ctx) }.takeIf { it.refCount > 0 }
        }.getOrNull() else null

        val sites = UsernameChecker.loadSites(ctx)
        val all = mutableListOf<SiteResult>()
        for ((idx, name) in names.withIndex()) {
            val label = "'$name' (${idx + 1}/${names.size})"
            val rows = UsernameChecker.checkAll(sites, name) { done, total, _ ->
                report("$label 확인 중", done, total)
                if (done % 10 == 0 || done == total) foreground("$label 확인 중 $done/$total", done, total)
                if (isStopped) throw InterruptedException()
            }
            if (matcher != null) {
                val withAvatar = rows.filter { it.avatar != null && it.status in setOf("found", "possible") }
                withAvatar.forEachIndexed { i, r ->
                    report("$label 프로필 사진 비교", i + 1, withAvatar.size)
                    r.faceScore = runCatching {
                        matcher.bestScore(FaceMatcher.decodeBytes(UsernameChecker.fetchBytes(r.avatar!!, 15_000)))
                    }.getOrNull()
                }
            }
            all += rows
        }
        all.sortWith(compareBy({ UsernameChecker.ORDER[it.status] }, { -(it.faceScore ?: -1.0) }, { it.site.lowercase() }))
        Store.saveResults(ctx, all)

        val found = all.count { it.status == "found" }
        val maybe = all.count { it.status == "possible" }
        val suspect = all.count { (it.faceScore ?: 0.0) >= FaceMatcher.SAME_PERSON }
        val msg = "완료: 있음 $found, 있을 수도 $maybe" + if (suspect > 0) ", 내 얼굴과 비슷한 프로필 $suspect" else ""
        runCatching {
            ctx.getSystemService(NotificationManager::class.java).notify(NOTI_DONE, notification(msg, false))
        }
        return Result.success()
    }
}
