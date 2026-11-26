package com.selfcheck.app

/** 네트워크 도구 전체 목록 (묶음별 목록을 합침) */
object NetToolbox {
    val ALL: List<NetTool> by lazy {
        IpTools.ALL + ConvertTools.ALL + CalcTools.ALL + RefTools.ALL + GenTools.ALL + DnsTools.ALL + DiagTools.ALL + GeoTools.ALL + ServerTools.ALL + WebTools.ALL + MailTools.ALL + SecTools.ALL + LogTools.ALL + PktTools.ALL + MakeTools.ALL
    }

    private val index: Map<String, NetTool> by lazy { ALL.associateBy { it.id } }
    fun byId(id: String): NetTool? = index[id]
}
