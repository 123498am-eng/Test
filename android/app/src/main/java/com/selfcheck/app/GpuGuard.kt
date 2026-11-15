package com.selfcheck.app

import android.app.ActivityManager
import android.app.Application
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.io.File

/**
 * GPU 안전장치: 일부 기기에서는 AI 모델의 GPU 가속을 켜다가 앱이 통째로 종료됩니다(네이티브 충돌이라 코드에서 못 잡음).
 * 켜기 전에 "시도 중" 표시를 남기고, 몇 초 동안 문제가 없으면 지웁니다. 표시가 남은 채로 앱이 다시 시작되면
 * 그 모델은 그 뒤로 CPU 를 씁니다. 그래서 같은 충돌이 반복되지 않습니다.
 */
object GpuGuard {
    private fun prefs(ctx: Context) = ctx.applicationContext.getSharedPreferences("gpu_guard", Context.MODE_PRIVATE)

    fun <T> create(ctx: Context, key: String, gpu: () -> T, cpu: () -> T): T {
        val p = prefs(ctx)
        if (p.getBoolean("bad_$key", false)) return cpu()
        if (p.getBoolean("try_$key", false)) { // 지난번에 GPU 를 켜다가 앱이 죽었음
            p.edit().putBoolean("bad_$key", true).remove("try_$key").commit()
            return cpu()
        }
        p.edit().putBoolean("try_$key", true).commit()
        val r = runCatching { gpu() }.getOrNull()
        if (r == null) { p.edit().putBoolean("bad_$key", true).remove("try_$key").commit(); return cpu() }
        // 첫 추론까지 문제없이 지나가면 표시를 지움
        Handler(Looper.getMainLooper()).postDelayed({ p.edit().remove("try_$key").apply() }, 8000)
        return r
    }
}

/** 앱 전체: 처리되지 않은 오류를 파일에 남겨 다음 실행 때 보여 줍니다. */
class SelfCheckApp : Application() {
    override fun onCreate() {
        super.onCreate()
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            runCatching { File(filesDir, "last_crash.txt").writeText("[${t.name}] " + android.util.Log.getStackTraceString(e)) }
            prev?.uncaughtException(t, e)
        }
    }

    companion object {
        /** 지난번 비정상 종료 내용 (없으면 null). 한 번 읽으면 지움. */
        fun takeCrashReport(ctx: Context): String? {
            val f = File(ctx.filesDir, "last_crash.txt")
            if (f.exists()) return f.readText().take(3000).also { f.delete() }
            // 네이티브 충돌 등은 시스템 기록에서 (Android 11 이상)
            if (Build.VERSION.SDK_INT >= 30) runCatching {
                val am = ctx.getSystemService(ActivityManager::class.java)
                val info = am.getHistoricalProcessExitReasons(ctx.packageName, 0, 1).firstOrNull() ?: return null
                val p = ctx.getSharedPreferences("gpu_guard", Context.MODE_PRIVATE)
                if (info.timestamp <= p.getLong("seen_exit", 0)) return null
                p.edit().putLong("seen_exit", info.timestamp).apply()
                if (info.reason == ApplicationExitInfo.REASON_CRASH_NATIVE || info.reason == ApplicationExitInfo.REASON_CRASH) {
                    val kind = if (info.reason == ApplicationExitInfo.REASON_CRASH_NATIVE) "네이티브 충돌 (GPU/AI 모델 쪽일 가능성)" else "앱 오류"
                    return "$kind\n${info.description ?: ""}\n\n다음부터 문제가 된 AI 모델은 CPU 로 실행됩니다."
                }
            }
            return null
        }
    }
}
