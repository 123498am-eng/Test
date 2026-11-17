package com.selfcheck.app

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.opencv.core.CvType
import org.opencv.core.Mat
import org.opencv.imgcodecs.Imgcodecs
import org.opencv.imgproc.Imgproc
import java.io.File
import kotlin.math.abs

/**
 * 피부 분석(SkinCore)을 파이썬 시제품과 같은 입력(얼굴 부분 사진, 얼굴 점, 피부 확률)으로 돌려 결과를 비교합니다.
 * 시험 사진: scikit-image 의 우주비행사 사진(NASA, 공개 저작물) + 주름을 그려 넣은 사진.
 */
class SkinCoreTest {
    companion object {
        @BeforeClass @JvmStatic fun load() { nu.pattern.OpenCV.loadLocally() }
        private val KEYS = mapOf("이마" to "이마", "미간" to "미간", "눈가L" to "왼쪽 눈가", "눈가R" to "오른쪽 눈가",
            "눈밑L" to "왼쪽 눈밑", "눈밑R" to "오른쪽 눈밑", "팔자L" to "왼쪽 팔자", "팔자R" to "오른쪽 팔자",
            "입가L" to "왼쪽 입가", "입가R" to "오른쪽 입가")
    }

    private fun res(name: String) = File(javaClass.classLoader!!.getResource("skin/$name")!!.toURI())

    private fun run(name: String, e: JSONObject): SkinResult {
        val bgr = Imgcodecs.imread(res("$name.png").absolutePath)
        val rgb = Mat(); Imgproc.cvtColor(bgr, rgb, Imgproc.COLOR_BGR2RGB)
        val p8 = Imgcodecs.imread(res("${name}_prob.png").absolutePath, Imgcodecs.IMREAD_GRAYSCALE)
        val prob = Mat(); p8.convertTo(prob, CvType.CV_32F, 1 / 255.0)
        val q = res("$name.q").readLines().filter { it.isNotBlank() }.map { it.trim().toFloat() }.toFloatArray()
        assertEquals(478 * 2, q.size)
        return SkinCore.analyze(rgb, q, e.getDouble("u").toFloat(), prob, e.getDouble("iod").toFloat(), 0f)
    }

    @Test fun wrinkleScoresMatchPythonPrototype() {
        val exp = JSONObject(res("expected.json").readText())
        for (name in listOf("astro_clean", "astro_syn")) {
            val e = exp.getJSONObject(name)
            val r = run(name, e)
            val sc = e.getJSONObject("scores")
            val report = StringBuilder()
            for ((py, kt) in KEYS) {
                val want = if (sc.isNull("주름:$py")) null else sc.getDouble("주름:$py").toFloat()
                val got = r.regionScores[kt]
                report.append("$kt python=$want kotlin=$got\n")
                if (want == null) assertNull("$name $kt\n$report", got)
                else { assertNotNull("$name $kt\n$report", got); assertTrue("$name $kt\n$report", abs(want - got!!) <= 6f) }
            }
            println("$name\n$report spots=${r.spots.size} (python ${e.getInt("spots")}) pores=${r.pores.size} overall=${r.overall}")
            r.metrics.forEach { println("  ${it.name}: ${"%.1f".format(it.degree)} (${it.value})") }
            println("  잔주름: ${r.fineScores}")
            println("  경고: ${r.warnings}")
        }
    }

    @Test fun syntheticWrinklesScoreHigherThanClean() {
        val exp = JSONObject(res("expected.json").readText())
        val clean = run("astro_clean", exp.getJSONObject("astro_clean"))
        val syn = run("astro_syn", exp.getJSONObject("astro_syn"))
        for (k in listOf("왼쪽 눈가", "오른쪽 눈가")) assertTrue(k, syn.regionScores[k]!! > clean.regionScores[k]!! + 20f)
        assertTrue(syn.regionScores["이마"]!! > 50f)
        val fc = clean.metrics.first { it.key == "fine" }.degree; val fs = syn.metrics.first { it.key == "fine" }.degree
        assertTrue("잔주름 clean=$fc syn=$fs", fs > fc)
        val wc = clean.metrics.first { it.key == "wrinkle" }.degree; val ws = syn.metrics.first { it.key == "wrinkle" }.degree
        assertTrue("주름 clean=$wc syn=$ws", ws > wc)
        assertTrue(syn.overall < clean.overall)
    }
}
