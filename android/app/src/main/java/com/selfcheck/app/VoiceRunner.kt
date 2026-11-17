package com.selfcheck.app

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.media.AudioAttributes
import android.media.AudioDeviceInfo
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Process
import android.provider.MediaStore
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.max
import kotlin.math.sqrt

/**
 * 마이크 → VoiceEngine → 스피커/이어폰을 실시간으로 이어 주는 오디오 스레드.
 * 지연을 줄이려고 저지연 AudioTrack 과 10ms 블록을 씁니다. 처리된 소리는 녹음해서 WAV 로 저장할 수도 있습니다.
 */
class VoiceRunner(private val ctx: Context, private val onStopped: (String?) -> Unit) {
    @Volatile var running = false; private set
    @Volatile var engine: VoiceEngine? = null; private set
    @Volatile var inLevel = 0f
    @Volatile var outLevel = 0f
    @Volatile var latencyMs = 0
    @Volatile var recording = false
    @Volatile var rate = 48000; private set
    private var thread: Thread? = null
    private val recChunks = ArrayList<ShortArray>()
    private var recSamples = 0L
    private val maxRecSeconds = 480

    companion object {
        /** 이어폰·헤드셋이 연결돼 있는지 (스피커로 내면 마이크에 다시 들어가 하울링이 남) */
        fun hasHeadphones(ctx: Context): Boolean {
            val am = ctx.getSystemService(AudioManager::class.java)
            return am.getDevices(AudioManager.GET_DEVICES_OUTPUTS).any {
                it.type in setOf(AudioDeviceInfo.TYPE_WIRED_HEADPHONES, AudioDeviceInfo.TYPE_WIRED_HEADSET, AudioDeviceInfo.TYPE_USB_HEADSET,
                    AudioDeviceInfo.TYPE_BLUETOOTH_A2DP, AudioDeviceInfo.TYPE_BLUETOOTH_SCO, AudioDeviceInfo.TYPE_HEARING_AID) ||
                    (Build.VERSION.SDK_INT >= 31 && it.type == AudioDeviceInfo.TYPE_BLE_HEADSET) ||
                    (Build.VERSION.SDK_INT >= 26 && it.type == AudioDeviceInfo.TYPE_USB_DEVICE)
            }
        }

        fun isBluetoothOutput(ctx: Context): Boolean {
            val am = ctx.getSystemService(AudioManager::class.java)
            return am.getDevices(AudioManager.GET_DEVICES_OUTPUTS).any { it.type == AudioDeviceInfo.TYPE_BLUETOOTH_A2DP || it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO }
        }
    }

    @SuppressLint("MissingPermission")
    fun start(initial: VoiceChain, setup: (VoiceEngine) -> Unit): String? {
        if (running) return null
        val am = ctx.getSystemService(AudioManager::class.java)
        val native = am.getProperty(AudioManager.PROPERTY_OUTPUT_SAMPLE_RATE)?.toIntOrNull() ?: 48000
        var rec: AudioRecord? = null; var chosen = 0
        for (r in listOf(native, 48000, 44100).distinct()) {
            val minRec = AudioRecord.getMinBufferSize(r, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
            if (minRec <= 0) continue
            val block = r / 100
            val sources = if (Build.VERSION.SDK_INT >= 29) listOf(MediaRecorder.AudioSource.VOICE_PERFORMANCE, MediaRecorder.AudioSource.MIC) else listOf(MediaRecorder.AudioSource.MIC)
            for (src in sources) {
                val a = runCatching { AudioRecord(src, r, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, max(minRec, block * 8)) }.getOrNull()
                if (a != null && a.state == AudioRecord.STATE_INITIALIZED) { rec = a; chosen = r; break } else a?.release()
            }
            if (rec != null) break
        }
        if (rec == null) return "마이크를 열 수 없습니다. 다른 앱이 마이크를 쓰고 있지 않은지, 권한이 허용됐는지 확인하세요."
        rate = chosen
        val block = rate / 100
        val minTrk = AudioTrack.getMinBufferSize(rate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val track = runCatching {
            AudioTrack.Builder()
                .setAudioAttributes(AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build())
                .setAudioFormat(AudioFormat.Builder().setEncoding(AudioFormat.ENCODING_PCM_16BIT).setSampleRate(rate).setChannelMask(AudioFormat.CHANNEL_OUT_MONO).build())
                .setBufferSizeInBytes(max(minTrk, block * 2 * 3))
                .setTransferMode(AudioTrack.MODE_STREAM)
                .setPerformanceMode(AudioTrack.PERFORMANCE_MODE_LOW_LATENCY)
                .build()
        }.getOrNull()
        if (track == null || track.state != AudioTrack.STATE_INITIALIZED) { rec.release(); track?.release(); return "소리를 내보낼 수 없습니다." }

        val eng = VoiceEngine(rate).also { it.setChain(initial); setup(it) }
        engine = eng
        latencyMs = (eng.latency * 1000L / rate).toInt() + (block * 3 * 1000L / rate).toInt() + (track.bufferSizeInFrames * 1000L / rate).toInt()
        running = true
        val r = rec
        thread = Thread({
            Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO)
            var err: String? = null
            val inS = ShortArray(block); val outS = ShortArray(block)
            val inF = FloatArray(block); val outF = FloatArray(block)
            try {
                r.startRecording(); track.play()
                track.write(ShortArray(block), 0, block) // 처음 한 블록은 무음으로 채워 끊김 방지
                while (running) {
                    val n = r.read(inS, 0, block)
                    if (n < 0) { err = "마이크 읽기 오류 ($n)"; break }
                    if (n == 0) continue
                    var si = 0.0
                    for (i in 0 until n) { val v = inS[i] / 32768f; inF[i] = v; si += v * v }
                    eng.process(inF, n, outF)
                    var so = 0.0
                    for (i in 0 until n) { val v = outF[i].coerceIn(-1f, 1f); so += v * v; outS[i] = (v * 32767f).toInt().toShort() }
                    track.write(outS, 0, n)
                    inLevel = sqrt(si / n).toFloat(); outLevel = sqrt(so / n).toFloat()
                    if (recording) synchronized(recChunks) {
                        if (recSamples < rate.toLong() * maxRecSeconds) { recChunks += outS.copyOf(n); recSamples += n } else recording = false
                    }
                }
            } catch (e: Throwable) { err = e.message ?: e.toString() }
            finally {
                running = false
                runCatching { r.stop() }; r.release()
                runCatching { track.stop() }; track.release()
                onStopped(err)
            }
        }, "voice-changer").also { it.start() }
        return null
    }

    fun stop() { running = false; thread?.join(800) }

    fun beginRecording() { synchronized(recChunks) { recChunks.clear(); recSamples = 0 }; recording = true }
    val recordedSeconds get() = synchronized(recChunks) { recSamples.toDouble() / rate }

    /** 녹음을 끝내고 WAV 로 저장. 성공하면 (보기용 이름, 공유용 Uri) */
    fun endRecordingAndSave(name: String): Pair<String, Uri>? {
        recording = false
        val data: ShortArray
        synchronized(recChunks) {
            if (recSamples <= 0) return null
            data = ShortArray(recSamples.toInt()); var p = 0
            for (c in recChunks) { System.arraycopy(c, 0, data, p, c.size); p += c.size }
            recChunks.clear(); recSamples = 0
        }
        val bytes = wav(data, rate)
        return if (Build.VERSION.SDK_INT >= 29) {
            val cv = ContentValues().apply {
                put(MediaStore.Audio.Media.DISPLAY_NAME, name); put(MediaStore.Audio.Media.MIME_TYPE, "audio/wav")
                put(MediaStore.Audio.Media.RELATIVE_PATH, Environment.DIRECTORY_MUSIC + "/SelfCheck")
            }
            val uri = ctx.contentResolver.insert(MediaStore.Audio.Media.EXTERNAL_CONTENT_URI, cv) ?: return null
            ctx.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
            "음악/SelfCheck/$name" to uri
        } else {
            val f = File(ctx.getExternalFilesDir(Environment.DIRECTORY_MUSIC), name)
            f.writeBytes(bytes)
            f.absolutePath to androidx.core.content.FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", f)
        }
    }

    private fun wav(x: ShortArray, rate: Int): ByteArray {
        val b = ByteBuffer.allocate(44 + x.size * 2).order(ByteOrder.LITTLE_ENDIAN)
        b.put("RIFF".toByteArray()).putInt(36 + x.size * 2).put("WAVEfmt ".toByteArray()).putInt(16).putShort(1).putShort(1)
            .putInt(rate).putInt(rate * 2).putShort(2).putShort(16).put("data".toByteArray()).putInt(x.size * 2)
        for (v in x) b.putShort(v)
        return b.array()
    }
}

/** 화면에서 고른 값 (엔진이 아직 없어도 보관) */
class VoiceSettings {
    @Volatile var presetId = "fem_natural"
    @Volatile var semitones = 0f
    @Volatile var formant = 1f
    @Volatile var fxAmount = 1f
    @Volatile var micGain = 1f
    fun apply(c: VoiceControls) { c.semitoneOffset = semitones; c.formantScale = formant; c.fxAmount = fxAmount; c.inputGain = micGain }
}
