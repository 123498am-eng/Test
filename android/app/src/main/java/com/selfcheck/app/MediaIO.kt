package com.selfcheck.app

import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Matrix
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaMetadataRetriever
import android.media.MediaMuxer
import android.net.Uri
import android.opengl.EGL14
import android.opengl.EGLConfig
import android.opengl.EGLContext
import android.opengl.EGLDisplay
import android.opengl.EGLExt
import android.opengl.EGLSurface
import android.opengl.GLES20
import android.opengl.GLUtils
import android.os.Build
import android.os.Environment
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import android.view.Surface
import java.io.Closeable
import java.io.File
import java.io.FileDescriptor
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.max
import kotlin.math.roundToInt

/** 동영상에서 프레임을 차례로 꺼냅니다 (회전 보정, 크기 줄이기 포함). */
class VideoSource(ctx: Context, uri: Uri) : Closeable {
    private val mmr = MediaMetadataRetriever().apply { setDataSource(ctx, uri) }
    private fun meta(k: Int) = mmr.extractMetadata(k)
    val durationMs = meta(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: 0L
    val frameCount = meta(MediaMetadataRetriever.METADATA_KEY_VIDEO_FRAME_COUNT)?.toIntOrNull() ?: 0
    private val rotation = meta(MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION)?.toIntOrNull() ?: 0
    private val rawW = meta(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)?.toIntOrNull() ?: 0
    private val rawH = meta(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)?.toIntOrNull() ?: 0
    val fps: Float = if (frameCount > 0 && durationMs > 0) (frameCount * 1000f / durationMs).coerceIn(5f, 60f) else 30f
    /** 프레임 수 (메타데이터에 없으면 길이 × 30fps 로 계산) */
    val count: Int = if (frameCount > 0) frameCount else (durationMs * 30 / 1000).toInt().coerceAtLeast(1)
    private val params = MediaMetadataRetriever.BitmapParams().apply { preferredConfig = Bitmap.Config.ARGB_8888 }

    /** start 번째부터 n개 프레임 (긴 변을 maxSide 이하로) */
    fun frames(start: Int, n: Int, maxSide: Int): List<Bitmap> {
        val list: List<Bitmap> = if (frameCount > 0) {
            runCatching { mmr.getFramesAtIndex(start, n.coerceAtMost(frameCount - start), params) }.getOrElse { emptyList() }
        } else {
            (start until minOf(start + n, count)).mapNotNull { i ->
                mmr.getFrameAtTime(i * 1_000_000L / 30, MediaMetadataRetriever.OPTION_CLOSEST)
            }
        }
        return list.map { fix(it, maxSide) }
    }

    private fun fix(b: Bitmap, maxSide: Int): Bitmap {
        val m = Matrix()
        // 일부 기기는 회전되지 않은 프레임을 줍니다: 원래 크기 그대로면 직접 돌립니다
        if (rotation != 0 && b.width == rawW && b.height == rawH && rawW != rawH) m.postRotate(rotation.toFloat())
        val sc = minOf(1f, maxSide.toFloat() / max(b.width, b.height))
        if (sc < 1f) m.postScale(sc, sc)
        if (m.isIdentity && b.config == Bitmap.Config.ARGB_8888) return b
        val out = Bitmap.createBitmap(b, 0, 0, b.width, b.height, m, true).copy(Bitmap.Config.ARGB_8888, false)
        b.recycle()
        return out
    }

    override fun close() = mmr.release()
}

/**
 * 비트맵을 차례로 받아 MP4(H.264)로 저장합니다. 생성, addFrame, finish 를 모두 같은 스레드에서 불러야 합니다.
 * width/height 는 16의 배수를 권장합니다.
 */
class VideoEncoder(fd: FileDescriptor, val width: Int, val height: Int, fps: Int) {
    private val codec = MediaCodec.createEncoderByType("video/avc")
    private val muxer = MediaMuxer(fd, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
    private var track = -1
    private var muxStarted = false
    private val info = MediaCodec.BufferInfo()
    private val surface: Surface
    private var display: EGLDisplay = EGL14.EGL_NO_DISPLAY
    private var context: EGLContext = EGL14.EGL_NO_CONTEXT
    private var eglSurface: EGLSurface = EGL14.EGL_NO_SURFACE
    private var prog = 0
    private var tex = 0
    private val quad = ByteBuffer.allocateDirect(16 * 4).order(ByteOrder.nativeOrder()).asFloatBuffer().apply {
        put(floatArrayOf(-1f, -1f, 0f, 1f, 1f, -1f, 1f, 1f, -1f, 1f, 0f, 0f, 1f, 1f, 1f, 0f)); position(0)
    }

    init {
        val fmt = MediaFormat.createVideoFormat("video/avc", width, height).apply {
            setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            setInteger(MediaFormat.KEY_BIT_RATE, (width * height * fps * 0.2f).toInt().coerceIn(1_000_000, 12_000_000))
            setInteger(MediaFormat.KEY_FRAME_RATE, fps)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 1)
        }
        codec.configure(fmt, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        surface = codec.createInputSurface()
        codec.start()
        setupEgl()
        setupGl()
    }

    private fun setupEgl() {
        display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
        val ver = IntArray(2)
        EGL14.eglInitialize(display, ver, 0, ver, 1)
        val attrs = intArrayOf(
            EGL14.EGL_RED_SIZE, 8, EGL14.EGL_GREEN_SIZE, 8, EGL14.EGL_BLUE_SIZE, 8, EGL14.EGL_ALPHA_SIZE, 8,
            EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT, 0x3142 /* EGL_RECORDABLE_ANDROID */, 1, EGL14.EGL_NONE)
        val configs = arrayOfNulls<EGLConfig>(1); val num = IntArray(1)
        EGL14.eglChooseConfig(display, attrs, 0, configs, 0, 1, num, 0)
        context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT,
            intArrayOf(EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE), 0)
        eglSurface = EGL14.eglCreateWindowSurface(display, configs[0], surface, intArrayOf(EGL14.EGL_NONE), 0)
        EGL14.eglMakeCurrent(display, eglSurface, eglSurface, context)
    }

    private fun setupGl() {
        fun sh(t: Int, src: String) = GLES20.glCreateShader(t).also { GLES20.glShaderSource(it, src); GLES20.glCompileShader(it) }
        prog = GLES20.glCreateProgram()
        GLES20.glAttachShader(prog, sh(GLES20.GL_VERTEX_SHADER,
            "attribute vec2 aPos; attribute vec2 aUV; varying vec2 vUV; void main(){ vUV=aUV; gl_Position=vec4(aPos,0.0,1.0); }"))
        GLES20.glAttachShader(prog, sh(GLES20.GL_FRAGMENT_SHADER,
            "precision mediump float; uniform sampler2D uTex; varying vec2 vUV; void main(){ gl_FragColor=texture2D(uTex,vUV); }"))
        GLES20.glLinkProgram(prog)
        val ids = IntArray(1); GLES20.glGenTextures(1, ids, 0); tex = ids[0]
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MAG_FILTER, GLES20.GL_LINEAR)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_WRAP_S, GLES20.GL_CLAMP_TO_EDGE)
        GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_WRAP_T, GLES20.GL_CLAMP_TO_EDGE)
    }

    /** ptsUs: 이 프레임의 시간(마이크로초) */
    fun addFrame(bmp: Bitmap, ptsUs: Long) {
        EGL14.eglMakeCurrent(display, eglSurface, eglSurface, context)
        GLES20.glViewport(0, 0, width, height)
        GLES20.glClearColor(0f, 0f, 0f, 1f)
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)
        GLES20.glUseProgram(prog)
        GLES20.glActiveTexture(GLES20.GL_TEXTURE0)
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, tex)
        GLUtils.texImage2D(GLES20.GL_TEXTURE_2D, 0, bmp, 0)
        val pos = GLES20.glGetAttribLocation(prog, "aPos"); val uv = GLES20.glGetAttribLocation(prog, "aUV")
        quad.position(0); GLES20.glEnableVertexAttribArray(pos); GLES20.glVertexAttribPointer(pos, 2, GLES20.GL_FLOAT, false, 16, quad)
        quad.position(2); GLES20.glEnableVertexAttribArray(uv); GLES20.glVertexAttribPointer(uv, 2, GLES20.GL_FLOAT, false, 16, quad)
        GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4)
        EGLExt.eglPresentationTimeANDROID(display, eglSurface, ptsUs * 1000)
        EGL14.eglSwapBuffers(display, eglSurface)
        drain(false)
    }

    private fun drain(end: Boolean) {
        var idle = 0
        while (true) {
            val idx = codec.dequeueOutputBuffer(info, 10_000)
            when {
                idx == MediaCodec.INFO_TRY_AGAIN_LATER -> { if (!end || ++idle > 300) return }
                idx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                    track = muxer.addTrack(codec.outputFormat); muxer.start(); muxStarted = true
                }
                idx >= 0 -> {
                    val buf = codec.getOutputBuffer(idx)
                    if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) info.size = 0
                    if (buf != null && info.size > 0 && muxStarted) {
                        buf.position(info.offset); buf.limit(info.offset + info.size)
                        muxer.writeSampleData(track, buf, info)
                    }
                    codec.releaseOutputBuffer(idx, false)
                    if (info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) return
                }
            }
        }
    }

    fun finish() {
        runCatching { codec.signalEndOfInputStream(); drain(true) }
        runCatching { codec.stop() }; codec.release()
        runCatching { if (muxStarted) muxer.stop() }; muxer.release()
        EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT)
        EGL14.eglDestroySurface(display, eglSurface)
        EGL14.eglDestroyContext(display, context)
        EGL14.eglTerminate(display)
        surface.release()
    }

    companion object {
        /** 인코더에 맞게 16의 배수로, 긴 변은 maxSide 이하로 */
        fun fitSize(w: Int, h: Int, maxSide: Int = 1280): Pair<Int, Int> {
            val sc = minOf(1f, maxSide.toFloat() / max(w, h))
            fun r(v: Float) = ((v / 16f).roundToInt() * 16).coerceAtLeast(16)
            return r(w * sc) to r(h * sc)
        }
    }
}

/** 갤러리(사진·동영상 폴더)에 저장합니다. */
object MediaSave {
    fun savePng(ctx: Context, bmp: Bitmap, name: String): String {
        if (Build.VERSION.SDK_INT >= 29) {
            val cv = ContentValues().apply {
                put(MediaStore.Images.Media.DISPLAY_NAME, name)
                put(MediaStore.Images.Media.MIME_TYPE, "image/png")
                put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/SelfCheck")
            }
            val uri = ctx.contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, cv)!!
            ctx.contentResolver.openOutputStream(uri)!!.use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
            return "사진/SelfCheck/$name"
        }
        val f = File(ctx.getExternalFilesDir(Environment.DIRECTORY_PICTURES), name)
        f.outputStream().use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
        return f.absolutePath
    }

    /** 새 동영상 파일을 만들고 (재생용 Uri, 쓰기용 파일, 완료 처리)를 돌려줍니다. */
    class VideoOut(val uri: Uri, val pfd: ParcelFileDescriptor, val label: String, private val onDone: () -> Unit) {
        fun done() { runCatching { pfd.close() }; onDone() }
    }

    fun newVideo(ctx: Context, name: String): VideoOut {
        if (Build.VERSION.SDK_INT >= 29) {
            val cv = ContentValues().apply {
                put(MediaStore.Video.Media.DISPLAY_NAME, name)
                put(MediaStore.Video.Media.MIME_TYPE, "video/mp4")
                put(MediaStore.Video.Media.RELATIVE_PATH, Environment.DIRECTORY_MOVIES + "/SelfCheck")
                put(MediaStore.Video.Media.IS_PENDING, 1)
            }
            val uri = ctx.contentResolver.insert(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, cv)!!
            val pfd = ctx.contentResolver.openFileDescriptor(uri, "rw")!!
            return VideoOut(uri, pfd, "동영상/SelfCheck/$name") {
                ctx.contentResolver.update(uri, ContentValues().apply { put(MediaStore.Video.Media.IS_PENDING, 0) }, null, null)
            }
        }
        val f = File(ctx.getExternalFilesDir(Environment.DIRECTORY_MOVIES), name)
        val pfd = ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_WRITE or ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_TRUNCATE)
        return VideoOut(Uri.fromFile(f), pfd, f.absolutePath) {}
    }
}
