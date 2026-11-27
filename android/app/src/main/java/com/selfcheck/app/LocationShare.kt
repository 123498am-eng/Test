package com.selfcheck.app

/**
 * 위치 공유 메시지 만들기 (순수 로직, 안드로이드 API 없음 — 시험하기 쉽게 따로 뺐어요).
 *
 * 가족·연인끼리 "지금 이 순간의 내 위치"를 한 번 지도 링크로 만들어, 보낼 사람과 보낼 앱을
 * 직접 골라 보내는 용도예요. 실시간으로 계속 보내는 추적 기능이 아니고, 버튼을 누를 때마다
 * 새로 만들어야 해요. 서버에 위치를 저장하지 않고, 공유하기 전까지는 이 글이 휴대폰 밖으로
 * 나가지 않아요.
 */
object LocationShare {
    /** 위도·경도가 있을 수 있는 범위인지 (0,0 은 GPS 를 못 받았을 때 나오는 깨진 값이라 제외) */
    fun isValidCoord(lat: Double, lon: Double): Boolean =
        lat.isFinite() && lon.isFinite() && lat in -90.0..90.0 && lon in -180.0..180.0 && !(lat == 0.0 && lon == 0.0)

    /** 구글 지도 공식 링크 형식 (developers.google.com/maps/documentation/urls/get-started).
     * 받는 사람 휴대폰에 구글 지도 앱이 있으면 앱으로, 없으면 웹 브라우저로 그 위치가 바로 열려요. */
    fun googleMapsLink(lat: Double, lon: Double): String = "https://www.google.com/maps/search/?api=1&query=%.6f,%.6f".format(lat, lon)

    /** 사람이 읽는 좌표 글자 (소수 6자리 ≈ 오차 10cm 수준이라 더 보여줘도 의미가 없어요) */
    fun formatCoord(v: Double): String = "%.6f".format(v)

    /** 위치 정확도(반경, m)를 사람이 이해할 설명으로 */
    fun accuracyLabel(accuracyM: Float?): String = when {
        accuracyM == null || !accuracyM.isFinite() || accuracyM <= 0f -> "정확도를 알 수 없어요"
        accuracyM < 20f -> "오차 반경 약 ${accuracyM.toInt()}m (정확한 편)"
        accuracyM < 100f -> "오차 반경 약 ${accuracyM.toInt()}m (보통)"
        else -> "오차 반경 약 ${accuracyM.toInt()}m (부정확해요 — 실내·건물 밀집 지역일 수 있어요)"
    }

    /** 위치를 가져온 지 얼마나 됐는지 — 오래된 위치를 최신인 것처럼 보내지 않도록 */
    fun ageLabel(fixMs: Long, nowMs: Long): String {
        val s = ((nowMs - fixMs) / 1000).coerceAtLeast(0)
        return when {
            s < 5 -> "방금 확인한 위치"
            s < 60 -> "${s}초 전 위치"
            s < 3600 -> "${s / 60}분 전 위치"
            else -> "${s / 3600}시간 전 위치 — 오래돼서 지금과 다를 수 있어요"
        }
    }

    /** 상대에게 보낼 글 (지도 링크 + 좌표 + 정확도 + 확인한 시각) */
    fun message(lat: Double, lon: Double, accuracyM: Float?, fixMs: Long, nowMs: Long): String = buildString {
        append("제 지금 위치예요 (").append(ageLabel(fixMs, nowMs)).append(")\n")
        append(googleMapsLink(lat, lon)).append('\n')
        append("좌표 ").append(formatCoord(lat)).append(", ").append(formatCoord(lon))
        if (accuracyM != null) append(" · ").append(accuracyLabel(accuracyM))
    }
}
