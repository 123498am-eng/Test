package com.selfcheck.app

import android.graphics.Bitmap
import android.util.Base64
import com.anthropic.client.AnthropicClient
import com.anthropic.client.okhttp.AnthropicOkHttpClient
import com.anthropic.core.JsonValue
import com.anthropic.models.beta.messages.BetaBase64ImageSource
import com.anthropic.models.beta.messages.BetaContentBlockParam
import com.anthropic.models.beta.messages.BetaJsonOutputFormat
import com.anthropic.models.beta.messages.BetaOutputConfig
import com.anthropic.models.beta.messages.BetaStopReason
import com.anthropic.models.beta.messages.MessageCreateParams
import org.json.JSONObject
import java.io.ByteArrayOutputStream

/** 제품 설명 (화면 왼쪽 위 패널에 표시). */
data class ProductInfo(
    val name: String,
    val brand: String,
    val category: String,
    val description: String,
    val features: List<String>,
    val source: String, // "Claude 분석" 또는 "기기 내 인식"
)

/**
 * 카메라에 비친 제품 사진을 Claude 에 보내 제품 이름과 설명을 받습니다.
 * 키는 사용자가 앱에 직접 입력하며, 사진은 사용자가 제품 인식 모드를 켰을 때만 전송됩니다.
 */
object ProductAI {
    private const val MODEL = "claude-opus-5-5"
    private var client: AnthropicClient? = null
    private var clientKey: String? = null

    private fun client(key: String): AnthropicClient {
        if (client == null || clientKey != key) {
            client = AnthropicOkHttpClient.builder().apiKey(key).build()
            clientKey = key
        }
        return client!!
    }

    private val schema: BetaJsonOutputFormat.Schema by lazy {
        val str = mapOf("type" to "string")
        BetaJsonOutputFormat.Schema.builder()
            .putAdditionalProperty("type", JsonValue.from("object"))
            .putAdditionalProperty("properties", JsonValue.from(mapOf(
                "name" to str,
                "brand" to str,
                "category" to str,
                "description" to str,
                "features" to mapOf("type" to "array", "items" to str),
            )))
            .putAdditionalProperty("required", JsonValue.from(listOf("name", "brand", "category", "description", "features")))
            .putAdditionalProperty("additionalProperties", JsonValue.from(false))
            .build()
    }

    private const val SYSTEM = """당신은 휴대폰 카메라에 비친 물건을 알아보고 한국어로 짧게 설명하는 도우미입니다.
사진 속 가장 눈에 띄는 제품 하나를 골라 답하세요.
- name: 제품 이름 (모델명을 알 수 있으면 포함, 모르면 일반 이름)
- brand: 브랜드 (알 수 없으면 "알 수 없음")
- category: 제품 종류
- description: 무엇에 쓰는 제품인지 2~3문장
- features: 눈에 보이는 특징이나 알아 두면 좋은 점 3가지 이내
확실하지 않은 부분은 "추정"이라고 밝히고, 사진에 사람이 있어도 사람에 대해서는 말하지 마세요."""

    fun describe(apiKey: String, image: Bitmap, hint: String?): ProductInfo {
        val jpeg = ByteArrayOutputStream().also { image.compress(Bitmap.CompressFormat.JPEG, 85, it) }.toByteArray()
        val b64 = Base64.encodeToString(jpeg, Base64.NO_WRAP)
        val prompt = if (hint != null) "기기의 사물 인식 결과는 '$hint' 입니다. 이 제품을 설명해 주세요." else "이 사진 속 제품을 설명해 주세요."

        val params = MessageCreateParams.builder()
            .model(MODEL)
            .maxTokens(8000L)
            .addBeta("server-side-fallback-2026-07-01")
            .fallbacksDefault()
            .outputConfig(BetaOutputConfig.builder()
                .effort(BetaOutputConfig.Effort.LOW)
                .format(BetaJsonOutputFormat.builder().schema(schema).build())
                .build())
            .system(SYSTEM)
            .addUserMessageOfContentBlockParams(listOf(
                BetaContentBlockParam.ofImage(BetaBase64ImageSource.builder()
                    .data(b64).mediaType(BetaBase64ImageSource.MediaType.IMAGE_JPEG).build()),
                BetaContentBlockParam.ofText(prompt),
            ))
            .build()

        val msg = client(apiKey).beta().messages().create(params)
        if (msg.stopReason().orElse(null) == BetaStopReason.REFUSAL) {
            throw IllegalStateException("이 사진은 분석할 수 없습니다")
        }
        val text = msg.content().mapNotNull { it.text().orElse(null)?.text() }.joinToString("")
        val o = JSONObject(text)
        val feats = o.optJSONArray("features")
        return ProductInfo(
            o.optString("name"), o.optString("brand"), o.optString("category"), o.optString("description"),
            (0 until (feats?.length() ?: 0)).map { feats!!.getString(it) },
            "Claude 분석",
        )
    }
}

/** 기기 안의 사물 인식(80종) 결과에 대한 기본 설명. 키가 없을 때 보여 줍니다. */
object LocalProducts {
    private val INFO = mapOf(
        "bicycle" to ("자전거" to "페달을 밟아 움직이는 두 바퀴 탈것입니다."),
        "car" to ("자동차" to "엔진이나 모터로 움직이는 승용 차량입니다."),
        "motorcycle" to ("오토바이" to "엔진으로 움직이는 두 바퀴 탈것입니다."),
        "bus" to ("버스" to "많은 사람을 태우는 대형 차량입니다."),
        "truck" to ("트럭" to "짐을 실어 나르는 화물 차량입니다."),
        "traffic light" to ("신호등" to "도로의 통행을 알려 주는 신호 장치입니다."),
        "fire hydrant" to ("소화전" to "불을 끌 때 물을 공급하는 장치입니다."),
        "stop sign" to ("정지 표지판" to "차량에 정지를 알리는 교통 표지입니다."),
        "bench" to ("벤치" to "여러 사람이 앉을 수 있는 긴 의자입니다."),
        "backpack" to ("백팩" to "등에 메는 가방입니다."),
        "umbrella" to ("우산" to "비나 햇빛을 가리는 도구입니다."),
        "handbag" to ("핸드백" to "손에 들거나 어깨에 메는 가방입니다."),
        "tie" to ("넥타이" to "셔츠 깃 아래에 매는 장식용 천입니다."),
        "suitcase" to ("여행 가방" to "여행할 때 짐을 넣는 바퀴 달린 가방입니다."),
        "frisbee" to ("프리스비" to "던지고 받으며 노는 원반입니다."),
        "skis" to ("스키" to "눈 위를 미끄러져 내려가는 운동 기구입니다."),
        "snowboard" to ("스노보드" to "눈 위를 타는 판 모양 운동 기구입니다."),
        "sports ball" to ("공" to "운동 경기에 쓰는 공입니다."),
        "kite" to ("연" to "바람을 이용해 하늘에 띄우는 놀이 기구입니다."),
        "baseball bat" to ("야구 배트" to "야구에서 공을 치는 방망이입니다."),
        "baseball glove" to ("야구 글러브" to "야구에서 공을 받는 장갑입니다."),
        "skateboard" to ("스케이트보드" to "바퀴 달린 판을 타는 운동 기구입니다."),
        "surfboard" to ("서핑보드" to "파도를 타는 판입니다."),
        "tennis racket" to ("테니스 라켓" to "테니스 공을 치는 라켓입니다."),
        "bottle" to ("병" to "음료나 액체를 담는 용기입니다."),
        "wine glass" to ("와인잔" to "와인을 마실 때 쓰는 손잡이 달린 잔입니다."),
        "cup" to ("컵" to "음료를 마시는 그릇입니다."),
        "fork" to ("포크" to "음식을 찍어 먹는 식기입니다."),
        "knife" to ("칼" to "음식을 자르는 도구입니다."),
        "spoon" to ("숟가락" to "음식을 떠먹는 식기입니다."),
        "bowl" to ("그릇" to "음식을 담는 오목한 식기입니다."),
        "banana" to ("바나나" to "노란 껍질의 열대 과일입니다."),
        "apple" to ("사과" to "둥글고 단단한 과일입니다."),
        "sandwich" to ("샌드위치" to "빵 사이에 재료를 넣은 음식입니다."),
        "orange" to ("오렌지" to "새콤달콤한 감귤류 과일입니다."),
        "broccoli" to ("브로콜리" to "초록색 꽃송이 모양의 채소입니다."),
        "carrot" to ("당근" to "주황색 뿌리채소입니다."),
        "hot dog" to ("핫도그" to "빵에 소시지를 끼운 음식입니다."),
        "pizza" to ("피자" to "반죽 위에 토핑을 올려 구운 음식입니다."),
        "donut" to ("도넛" to "고리 모양으로 튀긴 빵입니다."),
        "cake" to ("케이크" to "달콤하게 구운 디저트입니다."),
        "chair" to ("의자" to "한 사람이 앉는 가구입니다."),
        "couch" to ("소파" to "여러 사람이 앉을 수 있는 푹신한 의자입니다."),
        "potted plant" to ("화분" to "화분에 심은 식물입니다."),
        "bed" to ("침대" to "잠을 자는 가구입니다."),
        "dining table" to ("식탁" to "식사할 때 쓰는 탁자입니다."),
        "toilet" to ("변기" to "화장실의 위생 설비입니다."),
        "tv" to ("TV / 모니터" to "영상을 보여 주는 화면 장치입니다."),
        "laptop" to ("노트북" to "들고 다닐 수 있는 접이식 컴퓨터입니다."),
        "mouse" to ("마우스" to "컴퓨터 화면의 커서를 움직이는 입력 장치입니다."),
        "remote" to ("리모컨" to "TV 등 기기를 멀리서 조작하는 장치입니다."),
        "keyboard" to ("키보드" to "글자를 입력하는 컴퓨터 입력 장치입니다."),
        "cell phone" to ("휴대폰" to "전화, 메시지, 인터넷을 쓰는 휴대용 기기입니다."),
        "microwave" to ("전자레인지" to "전자파로 음식을 데우는 가전입니다."),
        "oven" to ("오븐" to "음식을 굽는 조리 기구입니다."),
        "toaster" to ("토스터" to "빵을 굽는 가전입니다."),
        "sink" to ("싱크대" to "물을 쓰고 설거지하는 개수대입니다."),
        "refrigerator" to ("냉장고" to "음식을 차갑게 보관하는 가전입니다."),
        "book" to ("책" to "글이나 그림을 엮은 인쇄물입니다."),
        "clock" to ("시계" to "시간을 알려 주는 장치입니다."),
        "vase" to ("꽃병" to "꽃을 꽂아 두는 병입니다."),
        "scissors" to ("가위" to "종이나 천을 자르는 도구입니다."),
        "teddy bear" to ("곰 인형" to "곰 모양의 봉제 인형입니다."),
        "hair drier" to ("헤어드라이어" to "머리를 말리는 가전입니다."),
        "toothbrush" to ("칫솔" to "이를 닦는 솔입니다."),
        "bird" to ("새" to "날개가 있는 동물입니다."),
        "cat" to ("고양이" to "반려동물로 많이 기르는 동물입니다."),
        "dog" to ("개" to "반려동물로 많이 기르는 동물입니다."),
    )

    fun korean(label: String) = INFO[label]?.first ?: label

    fun info(label: String) = INFO[label]?.let { (ko, desc) ->
        ProductInfo(ko, "-", "기본 사물", desc, emptyList(), "기기 내 인식")
    }
}
