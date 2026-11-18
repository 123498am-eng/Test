package com.selfcheck.app

import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** 사람이 만든 실제 음성(/tmp/voice_eval/in 폴더의 wav 파일)을 여러 설정으로 변환해 /tmp/voice_eval/out 에 저장 (분석은 파이썬에서). 폴더가 없으면 건너뜀. */
class VoiceEvalTest {
    private val cases: List<Pair<String, VoiceChain>> = listOf(
        "bypass" to VoiceChain(listOf(VoiceCfg()), 0f),
        "pitch_x1.5_noformant" to VoiceChain(listOf(VoiceCfg(semitones = 7.02f))),
        "pitch_x0.7_noformant" to VoiceChain(listOf(VoiceCfg(semitones = -6.17f))),
        "formant_1.2_only" to VoiceChain(listOf(VoiceCfg(formant = 1.2f))),
        "formant_0.85_only" to VoiceChain(listOf(VoiceCfg(formant = 0.85f))),
        "female_auto" to VoiceChain(listOf(VoiceCfg(targetHz = 205f, formantLink = 0.3f))),
        "child_auto" to VoiceChain(listOf(VoiceCfg(targetHz = 280f, formantLink = 0.4f, formant = 1.05f))),
        "deep_auto" to VoiceChain(listOf(VoiceCfg(targetHz = 95f, formantLink = 0.3f))),
        "robot_100" to VoiceChain(listOf(VoiceCfg(monotoneHz = 100f))),
        "autotune" to VoiceChain(listOf(VoiceCfg(snap = 1f))),
    )

    /** 추적기가 찾은 음높이를 5ms 간격으로 저장 (파이썬의 독립 추정과 비교) */
    @Test fun trackerDump() {
        val inDir = File("/tmp/voice_eval/in"); assumeTrue(inDir.isDirectory)
        for (f in inDir.listFiles { x -> x.name.endsWith(".wav") }!!) {
            val (fs, x) = VoiceTestUtil.readWav(f)
            val e = VoiceEngine(fs); e.setChain(VoiceChain(listOf(VoiceCfg())))
            VoiceTestUtil.run(e, x)
            val sb = StringBuilder()
            var t = 0L
            while (t < x.size) { val p = e.tracker.periodAt(t); sb.append("${t.toDouble() / fs},${if (p > 0) fs / p else 0f}\n"); t += (fs * 0.005).toLong() }
            File("/tmp/voice_eval/out/${f.nameWithoutExtension}.tracker.csv").writeText(sb.toString())
        }
    }

    /** 프리셋 48가지 전체를 실제 음성에 적용해 저장 */
    @Test fun allPresets() {
        val inDir = File("/tmp/voice_eval/in"); assumeTrue(inDir.isDirectory)
        for (f in inDir.listFiles { x -> x.name.endsWith(".wav") }!!.sortedBy { it.name }) {
            val (fs, x) = VoiceTestUtil.readWav(f)
            for (p in VoicePresets.ALL) {
                val e = VoiceEngine(fs); e.setChain(p.chain)
                VoiceTestUtil.writeWav(File("/tmp/voice_eval/presets/${f.nameWithoutExtension}__${p.id}.wav"), fs, VoiceTestUtil.run(e, x))
            }
        }
    }

    /** 자연스러움 측정용: /tmp/voice_eval/in2 의 여러 음성 x 대표 설정 → /tmp/voice_eval/out_(label.txt 의 이름) */
    @Test fun benchmark() {
        val inDir = File("/tmp/voice_eval/in2"); assumeTrue(inDir.isDirectory)
        val label = File("/tmp/voice_eval/label.txt").readText().trim()
        fun preset(id: String) = VoicePresets.byId(id)?.chain
        val cfgs = listOf(
            "bypass" to VoiceChain(listOf(VoiceCfg()), matchLevel = false),
            "pitch_x1.5" to VoiceChain(listOf(VoiceCfg(semitones = 7.02f)), matchLevel = false),
            "pitch_x2.0" to VoiceChain(listOf(VoiceCfg(semitones = 12f)), matchLevel = false),
            "pitch_x0.7" to VoiceChain(listOf(VoiceCfg(semitones = -6.17f)), matchLevel = false),
            "fem_natural" to preset("fem_natural")!!,
            "child" to preset("child")!!,
            "helium" to preset("helium")!!,
            "male_deep" to preset("male_deep")!!,
            "grandma" to preset("grandma")!!,
            "opera" to preset("opera")!!,
        )
        for (f in inDir.listFiles { x -> x.name.endsWith(".wav") }!!.sortedBy { it.name }) {
            val (fs, x) = VoiceTestUtil.readWav(f)
            for ((name, chain) in cfgs) {
                val e = VoiceEngine(fs); e.setChain(chain)
                VoiceTestUtil.writeWav(File("/tmp/voice_eval/out_$label/${f.nameWithoutExtension}__$name.wav"), fs, VoiceTestUtil.run(e, x))
            }
        }
    }

    /** 조각마다 의도한 음높이를 저장 (엔진 의도 vs 출력에서 측정한 음높이 비교용) */
    @Test fun traceDump() {
        val inDir = File("/tmp/voice_eval/in2"); assumeTrue(inDir.isDirectory)
        val label = File("/tmp/voice_eval/label.txt").readText().trim()
        for (n in listOf("m_mid", "f_mid", "ko_m")) for ((cn, semi) in listOf("x1.5" to 7.02f, "x2.0" to 12f)) {
            val (fs, x) = VoiceTestUtil.readWav(File(inDir, "$n.wav"))
            val e = VoiceEngine(fs); e.setChain(VoiceChain(listOf(VoiceCfg(semitones = semi)), matchLevel = false))
            val sb = StringBuilder()
            val inb = FloatArray(480); val ob = FloatArray(480)
            val padded = x + FloatArray(((x.size + e.latency + 479) / 480) * 480 - x.size)
            val out = FloatArray(padded.size)
            var p = 0
            while (p + 480 <= padded.size) {
                System.arraycopy(padded, p, inb, 0, 480)
                e.process(inb, 480, ob)
                if (p == 0) e.debugVoice?.trace = { t, fi, fo, v -> sb.append("$t,$fi,$fo,$v\n") }
                System.arraycopy(ob, 0, out, p, 480); p += 480
            }
            File("/tmp/voice_eval/out_$label/trace_${n}_$cn.csv").writeText(sb.toString())
            VoiceTestUtil.writeWav(File("/tmp/voice_eval/out_$label/trace_${n}_$cn.wav"), fs, out.copyOfRange(e.latency, e.latency + x.size))
        }
    }

    /** 모든 프리셋 x in2 의 여러 음성 → /tmp/voice_eval/pres2 */
    @Test fun presetsOnAllInputs() {
        val inDir = File("/tmp/voice_eval/in2"); assumeTrue(inDir.isDirectory)
        for (f in inDir.listFiles { x -> x.name.endsWith(".wav") }!!.sortedBy { it.name }) {
            val (fs, x) = VoiceTestUtil.readWav(f)
            for (p in VoicePresets.ALL) {
                val e = VoiceEngine(fs); e.setChain(p.chain)
                VoiceTestUtil.writeWav(File("/tmp/voice_eval/pres2/${f.nameWithoutExtension}__${p.id}.wav"), fs, VoiceTestUtil.run(e, x))
            }
        }
    }

    @Test fun synthDump() {
        assumeTrue(File("/tmp/voice_eval").isDirectory)
        val fs = 44100
        val x = VoiceTestUtil.vowel(fs, 4.0, { t -> 120.0 * (1 + 0.04 * Math.sin(2 * Math.PI * 0.7 * t)) }, listOf(700.0 to 80.0, 1200.0 to 90.0, 2600.0 to 120.0))
        VoiceTestUtil.writeWav(File("/tmp/voice_eval/synth/in.wav"), fs, x)
        for ((n, c) in listOf("p5" to VoiceChain(listOf(VoiceCfg(semitones = 5f))), "f125" to VoiceChain(listOf(VoiceCfg(formant = 1.25f))), "p0" to VoiceChain(listOf(VoiceCfg())))) {
            val e = VoiceEngine(fs); e.setChain(c)
            VoiceTestUtil.writeWav(File("/tmp/voice_eval/synth/$n.wav"), fs, VoiceTestUtil.run(e, x))
        }
    }

    @Test fun run() {
        val inDir = File("/tmp/voice_eval/in"); assumeTrue(inDir.isDirectory)
        for (f in inDir.listFiles { x -> x.name.endsWith(".wav") }!!.sortedBy { it.name }) {
            val (fs, x) = VoiceTestUtil.readWav(f)
            for ((name, chain) in cases) {
                val e = VoiceEngine(fs); e.setChain(chain)
                val t0 = System.nanoTime()
                val y = VoiceTestUtil.run(e, x)
                val ms = (System.nanoTime() - t0) / 1e6
                VoiceTestUtil.writeWav(File("/tmp/voice_eval/out/${f.nameWithoutExtension}__$name.wav"), fs, y)
                println("${f.name} $name: ${"%.0f".format(ms)}ms for ${"%.1f".format(x.size.toDouble() / fs)}s audio, underruns=${e.underruns}, userF0=${"%.0f".format(e.tracker.userF0)}")
            }
        }
    }
}
