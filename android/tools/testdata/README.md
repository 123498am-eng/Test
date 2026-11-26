# 시험용 기준 자료 만들기

앱의 시험(`android/app/src/test`)은 **Kotlin 코드와 다른 구현**이 계산한 값과 비교해요. 그 값을 만든 스크립트를 모아 두었어요.
스크립트는 결과 파일을 `android/app/src/test/resources/…`(또는 `NetSecVectors.kt`)에 써요. 시험을 돌릴 때는 이 스크립트가 필요 없어요(결과 파일이 저장소에 들어 있어요).

| 스크립트 | 만드는 것 | 기준이 된 구현 |
|---|---|---|
| `gen_sec_vectors.py` · `emit_sec_kotlin.py` · `cvss_ref.py` | 보안·암호 도구 기준값(`NetSecVectors.kt`) | `cryptography`, `hashlib`, `openssl`, 독립 CVSS 공식 |
| `gen_logs.py` | 로그 분석 시험용 로그와 "심어 둔 정답"(`resources/netlog`) | 씨앗 고정 난수 + 파이썬이 따로 센 값 |
| `capture_tls.py` | 실제 TLS Hello 바이트(`resources/netpkt/tls`) | 로컬 `openssl s_client`·파이썬 `ssl` 이 실제로 보낸 바이트 |
| `gen_pkt_vectors.py` · `gen_pkt_vectors2.py` | 패킷·pcap·pcapng·체크섬·JA3·캡처 필터(`resources/netpkt`) | `scapy`(만들기), `dpkt`(읽기), `libpcap`(BPF 컴파일·실행) |
| `gen_make_vectors.py` | cron·IPv6 ULA·WireGuard·WPA 기준값(`resources/netmake`) | `croniter`, `hashlib`+`ipaddress`, `cryptography`(X25519), `hashlib.pbkdf2_hmac` |
| `build_ipdb.py` | 앱에 들어 있는 오프라인 IP 자료(`assets/ipdb`) | DB-IP Lite 국가·ASN (CC BY 4.0) |

필요한 파이썬 패키지(시험 자료를 다시 만들 때만): `pip install scapy dpkt croniter cryptography`
(마지막으로 만들 때 버전: scapy 2.8.0, dpkt 1.9.8, croniter 7.0.0, libpcap 1.10.4, OpenSSL 3.0).
`gen_pkt_vectors.py <출력폴더> <TLS 폴더>` 처럼 인자를 받는 스크립트는 파일 첫머리의 설명을 보세요.

설정 만들기 도구(nftables·systemd·netplan·chrony·fail2ban·HAProxy·sshd·tc·OpenSSL)의 시험은 만든 설정을 **실제 도구**
(`nft -c`, `systemd-analyze verify`, `netplan generate`, `chronyd -p`, `fail2ban-client -t`, `haproxy -c`, `sshd -t`, `tc`, `openssl`, `wg`, `ssh-keygen`)에
넣어서 통과하는지 확인해요. 도구가 없는 컴퓨터에서는 그 시험이 자동으로 건너뛰어져요(`Assume`). 장비를 바꾸는 명령은 쓰지 않아요
(검사 모드만, `tc` 는 없는 장치 이름으로 문법만).
