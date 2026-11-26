package com.selfcheck.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/*
 * 오프라인 IP 자료(DB-IP Lite 를 줄여 넣은 이진 파일) 조회 시험.
 * 정답은 원본 CSV 를 파이썬(bisect)으로 따로 찾아서 만든 값이라, 파일 만들기·읽기·이진 탐색을 모두 확인합니다.
 */
class NetGeoTest {
    private val db get() = FileHost.db

    private val VECTORS = """
8.8.8.8|US|15169|Google LLC
8.8.4.4|US|15169|Google LLC
1.1.1.1|AU|13335|Cloudflare, Inc.
1.0.0.1|AU|13335|Cloudflare, Inc.
9.9.9.9|US|19281|Quad9
168.126.63.1|KR|4766|Korea Telecom
168.126.63.2|KR|4766|Korea Telecom
210.220.163.82|KR|9318|SK Broadband Co Ltd
164.124.101.2|KR|3786|LG DACOM Corporation
203.0.113.5||0|
192.0.2.1||0|
10.0.0.1||0|
192.168.0.1||0|
127.0.0.1||0|
0.0.0.0||0|
255.255.255.255||0|
223.255.255.255|AU|0|
23.0.0.1|US|20940|Akamai International B.V.
52.95.110.1|US|16509|Amazon.com, Inc.
121.132.168.171|KR|4766|Korea Telecom
113.226.115.168|CN|4837|CHINA UNICOM China169 Backbone
8.28.82.83|US|3356|Level 3 Communications, Inc.
159.185.53.52|US|0|
171.210.217.242|CN|4134|Chinanet
249.63.228.46||0|
20.190.9.171|US|8075|Microsoft Corporation
219.20.158.71|JP|17676|SoftBank Corp.
74.149.144.42|US|8075|Microsoft Corporation
83.35.69.27|ES|3352|TELEFONICA DE ESPANA S.A.U.
163.174.110.104|NO|57506|Politiets IKT-tjenester (PIT)
57.148.105.62|IE|0|
161.219.247.33|US|0|
160.97.174.20|IT|137|Consortium GARR
75.106.85.81|US|7155|ViaSat,Inc.
26.166.21.169|US|749|United States Department of Defense (DoD)
104.123.37.59|US|20940|Akamai International B.V.
88.86.195.42|RU|28890|INSYS LLC
63.19.123.112|US|701|Verizon Business
139.58.21.53|SE|197425|Saab AB
201.207.8.0|CR|11830|Instituto Costarricense de Electricidad y Telecom.
32.221.83.134|US|46690|Verizon Business
137.50.130.147|GB|786|Jisc Services Limited
167.33.61.254|CA|0|
244.160.45.146||0|
145.158.155.199|NL|1103|SURF B.V.
218.128.160.189|JP|17676|SoftBank Corp.
103.209.25.31|AU|58915|Serversaurus
100.205.23.21|US|21928|T-Mobile USA, Inc.
177.76.245.25|BR|26599|TELEFONICA BRASIL S.A
94.78.241.11|RU|12389|PJSC Rostelecom
253.149.88.140||0|
95.15.44.2|TR|9121|Turk Telekomunikasyon Anonim Sirketi
52.77.4.203|SG|16509|Amazon.com, Inc.
126.77.23.61|JP|17676|SoftBank Corp.
213.97.202.183|ES|3352|TELEFONICA DE ESPANA S.A.U.
19.49.30.145|US|0|
146.158.4.226|RU|43849|Sever-Svyaz LLC
185.240.146.15|BG|51582|Cifrova Kabelna Korporacia EOOD
60.133.185.48|JP|17676|SoftBank Corp.
182.67.237.244|IN|45609|Bharti Airtel Limited
197.225.251.91|MU|23889|MauritiusTelecom
202.159.29.174|ID|9340|INDO Internet, PT
27.11.90.146|CN|4837|CHINA UNICOM China169 Backbone
90.10.200.16|FR|3215|Orange S.A.
248.108.103.179||0|
154.50.62.174|CA|55066|eStruxture Data Centers Inc.
254.206.107.152||0|
101.238.40.222|CN|0|
65.146.116.212|US|209|CenturyLink Communications, LLC
134.155.124.61|DE|553|Universitaet Stuttgart
93.162.65.6|DK|3292|TDC Holding A/S
66.159.219.247|FR|394089|Google LLC
9.84.84.156|CA|0|
106.157.244.156|JP|2516|KDDI CORPORATION
75.206.226.106|US|6167|Verizon Business
7.51.145.165|US|749|United States Department of Defense (DoD)
45.83.177.7|UA|56380|''IT FRUIT'' S.R.L.
117.127.49.37|CN|0|
86.200.167.249|FR|3215|Orange S.A.
46.103.219.233|GR|3329|VODAFONE-PANAFON HELLENIC TELECOMMUNICATIONS COMPANY SA
34.4.37.221|US|43515|Google Ireland Limited
34.174.9.3|US|396982|Google LLC
54.35.172.97|US|16509|Amazon.com, Inc.
240.8.140.252||0|
159.100.43.120|FR|34949|IDLINE SAS
87.128.124.219|DE|3320|Deutsche Telekom AG
202.227.58.254|JP|4725|SoftBank Corp.
227.93.108.17||0|
211.101.95.201|JP|0|
199.177.58.168|US|0|
118.226.80.123|CN|0|
158.219.141.146|US|0|
197.195.14.17|EG|36992|ETISALAT MISR
86.147.102.50|GB|2856|British Telecommunications PLC
103.27.90.150|NZ|0|
154.242.96.84|DZ|36947|Telecom Algeria
192.143.83.44|ZA|37611|AFRIHOST SP (PTY) LTD
254.3.192.228||0|
146.210.84.215|AT|42114|PG Austria GmbH
200.60.42.141|PE|6147|Telefonica del Peru S.A.A.
115.228.95.206|CN|4134|Chinanet
110.51.18.176|CN|45113|Shanxi Datong Coal Group Communication Co., Ltd
23.209.4.246|BR|16625|Akamai Technologies, Inc.
213.81.225.125|SK|6855|Slovak Telekom, a.s.
111.252.71.152|TW|3462|Chunghwa Telecom Co., Ltd.
181.129.15.10|CO|13489|EPM Telecomunicaciones S.A. E.S.P.
134.178.37.66|AU|140637|Macquarie Technology Operations Pty Limited
0.37.205.127||0|
126.136.4.24|JP|0|
34.210.250.133|US|16509|Amazon.com, Inc.
152.23.125.70|US|36850|University of North Carolina at Chapel Hill
165.92.175.217|US|0|
153.239.30.110|JP|4713|NTT Communications Corporation
10.67.254.136||0|
136.79.49.102|US|396982|Google LLC
51.121.149.159|DE|16509|Amazon.com, Inc.
138.219.42.5|AR|27823|Dattatec.com
224.80.70.238||0|
142.113.226.73|CA|577|Bell Canada
21.122.128.96|US|749|United States Department of Defense (DoD)
107.135.164.220|US|7018|AT&T Enterprises, LLC
164.80.221.89|AU|9880|NextGen.Net Pty Ltd
196.143.111.65|EG|36935|Vodafone Data
71.99.69.229|US|701|Verizon Business
178.243.211.29|TR|16135|TURKCELL ILETISIM HIZMETLERI A.S.
151.75.106.50|IT|1267|WIND TRE S.P.A.
185.243.221.72|RU|0|
210.116.46.231|KR|9848|SEJONG NETWORKS
127.220.59.29||0|
29.176.109.229|US|749|United States Department of Defense (DoD)
121.146.59.32|KR|4766|Korea Telecom
169.32.165.234|CH|0|
109.175.49.172|BA|9146|BH Telecom d.d. Sarajevo
145.209.112.228|NL|1101|SURF B.V.
82.142.252.45|GB|0|
101.225.163.150|CN|4812|China Telecom (Group)
249.152.117.101||0|
144.60.95.17|US|25993|AT&T Enterprises, LLC
243.233.180.85||0|
45.59.151.136|CA|0|
103.138.35.129|PG|0|
68.169.100.170|NL|400799|Pufferfish Studios LLC
212.35.116.2|BE|8220|COLT Technology Services Group Limited
185.184.45.85|FI|0|
83.168.139.13|SK|5578|SWAN, a.s.
83.166.64.109|GB|43009|Infobip Limited
149.14.98.235|FR|174|Cogent Communications
15.177.102.231|MX|16509|Amazon.com, Inc.
62.205.39.33|GR|702|Verizon Business
138.252.175.187|PK|154348|Sky47 Limited
193.41.115.185|NL|60781|LeaseWeb Netherlands B.V.
102.221.212.208|MU|0|
4.47.187.101|US|3356|Level 3 Communications, Inc.
198.124.239.19|NL|291|ESnet
23.128.223.132|TW|0|
185.240.58.150|IR|204787|FANAVARAN NOVIN BONYAN PASARGAD Co., (psj)
52.120.95.85|US|8075|Microsoft Corporation
57.158.242.230|US|8075|Microsoft Corporation
85.255.30.46|FR|13150|CATO NETWORKS LTD
45.58.36.138|CA|6364|Atlantic.net, Inc.
102.131.32.77|EG|0|
23.211.48.157|TR|16625|Akamai Technologies, Inc.
199.6.1.235|NL|30132|Internet Systems Consortium, Inc.
5.157.24.31|EE|58065|Orion Network Limited
51.77.222.148|FR|16276|OVH SAS
94.176.117.219|IT|207990|HostRoyale Technologies Pvt Ltd
203.0.1.145|AU|0|
190.8.166.132|VE|264628|CORPORACION FIBEX TELECOM, C.A.
32.106.217.252|US|2686|AT&T Corp.
168.76.250.25|ZA|137951|ASLINE LIMITED
105.19.5.196|FR|37100|SEACOM Limited
23.236.166.14|CA|55286|B2 Net Solutions Inc.
136.96.4.252|US|0|
9.246.153.192|UA|14593|Space Exploration Technologies Corporation
130.117.52.145|FR|174|Cogent Communications
208.93.164.151|CA|398839|Alliance Telecom
92.63.67.23|RU|8510|Tomsk State University
136.176.161.201|GB|199741|TransitX Ltd
178.170.111.137|FR|21409|Ikoula Net SAS
45.43.147.165|GE|13335|Cloudflare, Inc.
38.110.215.111|CA|174|Cogent Communications
200.0.143.96|MX|0|
196.210.47.7|GB|20011|Dimension Data
1.0.2.51|CN|0|
192.33.246.13|DE|31898|Oracle Corporation
172.225.181.82|VN|36183|Akamai Technologies, Inc.
221.120.167.89|AU|64098|TASMANET
37.218.245.252|NL|47172|Greenhost BV
178.208.75.188|CZ|216139|Iron Hosting Centre LTD
173.212.194.100|DE|51167|Contabo GmbH
193.35.93.245|CZ|59959|SferiaNET.cz s.r.o.
193.109.233.65|IT|0|
103.170.117.138|IN|16276|OVH SAS
176.25.186.62|AT|17404|Pipe Networks LLC
79.127.135.177|AU|212238|Datacamp Limited
198.54.182.84|US|62807|NETARYX LLC
198.64.105.241|BD|203020|HostRoyale Technologies Pvt Ltd
103.187.85.239|IN|133661|Netplus Broadband Services Private Limited
103.96.132.82|AU|136804|Wireless Innovation Pty Ltd
84.39.158.144|ES|0|
167.114.79.206|CA|16276|OVH SAS
63.75.61.20|US|10461|Eze Castle Software LLC
194.187.208.122|US|11404|Wave Broadband
213.154.26.75|AZ|28787|Aztelekom LLC
91.235.78.226|FR|205537|Scaleway SAS
23.132.230.89|TW|0|
114.134.14.222|NZ|45267|Lightwire Limited
114.142.170.175|ID|4761|PT. INDOSAT Tbk
153.52.174.164|US|399114|Hyonix
23.203.157.83|JP|20940|Akamai International B.V.
205.198.115.223|SG|153560|STACKS NETWORK PTE. LTD.
217.182.37.21|GB|16276|OVH SAS
216.246.29.0|PA|23352|DEFT.COM
212.135.250.245|US|3257|GTT Communications Inc.
66.175.105.203|DO|701|Verizon Business
193.247.192.59|NO|31169|Sognenett AS
172.216.185.130|FR|209854|Cyberzone S.A.
103.153.49.217|BD|140906|MAYA SOFT
160.48.160.223|NL|1136|KPN B.V.
64.39.24.254|MX|33070|Rackspace Hosting
212.3.230.77|NL|3356|Level 3 Communications, Inc.
203.119.126.124|HK|0|
40.96.64.39|IE|8075|Microsoft Corporation
217.65.65.233|IT|0|
216.128.167.139|US|20473|The Constant Company, LLC
77.70.181.4|US|44431|Marlink AS
217.217.55.240|US|7029|Windstream Communications LLC
38.60.217.180|PK|154177|LIGHT NODE LIMITED
195.40.75.234|DE|3257|GTT Communications Inc.
196.207.21.42|KE|15808|AccessKenya Group
203.21.140.201|WS|135409|Kacific Broadband Satellites Pte Ltd
174.137.155.192|US|27257|Webair Internet Development Company Inc.
154.209.156.3|TR|44559|IT HOSTLINE LTD
200.123.57.96|AR|52444|Pogliotti & Pogliotti Construcciones S.A.
136.0.170.238|DE|8881|1&1 Versatel GmbH
23.128.4.59|GD|401400|MCNET-SOLUTIONS
220.113.129.229|CN|0|
78.153.83.110|DE|12759|Stephan Fuss trading as SoftCom Datensysteme
170.78.124.155|AR|263780|Global Telecomunicaciones SRL
194.164.216.51|GB|57043|HOSTKEY B.V.
51.103.202.127|CH|8075|Microsoft Corporation
103.152.12.12|MY|140710|NKH SOLUTION SDN BHD
174.120.241.210|US|36351|IBM Cloud
66.205.241.184|US|0|
192.139.131.135|AU|0|
160.206.150.112|US|0|
158.69.105.130|CO|16276|OVH SAS
103.131.240.66|CN|0|
109.108.121.213|CZ|42908|O2 Czech Republic, a.s.
197.89.27.199|ZA|20011|Dimension Data
134.159.120.44|AU|4637|Telstra International Limited
45.60.160.146|GB|19551|Incapsula Inc
192.25.179.244|KR|4766|Korea Telecom
181.189.230.117|HN|27696|Columbus Networks de Honduras S. de R.L.
200.10.158.61|CL|52315|Servicios de Administracion Previsional S.A.
149.6.166.14|FR|174|Cogent Communications
74.245.199.27|PH|14593|Space Exploration Technologies Corporation
185.230.180.106|NL|0|
204.10.241.139|CA|14453|ADVANCED KNOWLEDGE NETWORKS
103.25.255.235|HK|58779|i4HK Limited
69.16.44.76|US|1929|University of Massachusetts - AMHERST
195.54.170.79|NO|9009|M247 Europe SRL
46.229.244.84|GB|202020|Flexgrid Ltd
172.121.156.29|US|3257|GTT Communications Inc.
185.171.103.119|RU|50166|RTCloud, LLC
103.69.108.171|PH|131306|CITI Cableworld Inc.
113.17.248.18|CN|4134|Chinanet
67.203.220.225|PR|11992|Liberty Mobile Puerto Rico Inc.
189.0.202.245|BR|27699|TELEFONICA BRASIL S.A
159.247.2.42|US|3481|State of Connecticut
207.91.92.50|US|2914|NTT America, Inc.
193.247.165.14|GB|43872|Optinet U.K. Limited
72.167.10.87|US|398101|GoDaddy.com, LLC
57.188.30.58|GB|205080|Societe Internationale de Telecommunications Aeronautiques
38.91.47.21|US|397596|Assured DP
193.142.151.254|IL|42647|Automatic Bank Services Limited
15.20.104.109|GB|2154|HP Inc.
133.75.169.222|JP|9591|National Institute for Fusion Science
205.167.185.220|US|10796|Charter Communications Inc
117.131.19.241|CN|24400|China Mobile Communications Group Co., Ltd
128.211.120.134|US|397501|Purdue University
163.5.21.57|FR|56339|Ionis Group - Ionis Schools of Technology and Management SAS
46.34.18.83|JP|210162|UAB Cherry Servers
204.193.224.108|US|10616|National Oceanic and Atmospheric Administration
180.235.107.239|NZ|135069|Feenix Communications Limited
185.84.106.192|LB|42828|Top Net SARL
220.244.147.163|AU|2764|AAPT Limited
217.194.20.125|NL|38930|LeaseWeb Network B.V.
91.230.73.21|GB|50131|Spartan Host Ltd
98.124.135.240|MY|3257|GTT Communications Inc.
89.187.28.251|JP|396356|Latitude.sh
178.93.145.221|VN|214143|SKYDIGITAL TELECOM LTD
45.149.39.232|FR|212609|Karolio IT paslaugos, UAB
86.38.28.7|LT|212046|UAB "Bite Lietuva"
23.180.96.142|US|152179|GLOBAL COMMUNICATION NETWORK LIMITED
170.82.96.184|PE|27843|OPTICAL TECHNOLOGIES S.A.C.
103.176.213.182|IN|137109|Grace Teleinfra Pvt Ltd
185.111.9.21|IR|201540|Pishgaman Toseeh Fanavari Etelaat Va Ertebatat Jonoub (Joint Stock Company)
167.253.22.96|IT|402236|Patriot Broadband LLC
64.34.87.156|NL|262287|Maxihost LTDA
82.41.75.235|HK|9304|HGC Global Communications Limited
220.228.70.241|TW|4780|Digital United Inc.
192.147.57.174|US|6303|Barclays Capital
8.7.43.244|US|53316|CHEETAHMAIL
199.216.99.90|CA|15296|Cybera Inc
103.5.79.230|HK|134753|West Kowloon Cultural District Authority
194.87.203.49|RU|3312|IT Energy Service LLC
66.228.83.35|CA|397130|SmartLayer Business Solutions
103.93.8.74|IN|45117|Ishan's Network
8.41.251.72|US|3356|Level 3 Communications, Inc.
72.135.149.246|US|10796|Charter Communications Inc
200.11.30.241|NI|14754|Telgua
36.137.127.9|CN|9808|China Mobile Communications Group Co., Ltd
185.87.134.110|DE|8075|Microsoft Corporation
64.4.169.219|US|41095|IPTP LTD
136.143.254.44|US|10753|Level 3 Communications, Inc.
145.14.90.37|TR|4809|China Telecom Next Generation Carrier Network
186.82.101.154|CO|10620|Telmex Colombia S.A.
185.106.193.102|PT|42689|Glide Student & Residential Limited
49.79.135.32|CN|4134|Chinanet
185.224.59.15|SE|49419|Iver Sverige AB
148.168.80.94|US|7068|Pfizer Inc.
24.175.185.1|US|11427|Charter Communications Inc
89.20.112.64|RU|12389|PJSC Rostelecom
94.229.28.79|RU|48470|Joint Stock Company MTU Kristall
217.180.28.210|GB|5503|RM Education Ltd
168.228.188.179|BR|264928|M LEONARA FREITAS DA SILVA FIBRANET COM E MULT
179.42.28.234|BR|271124|Jsm da Silva me
95.161.252.31|FI|50952|Global Network Management Inc
91.109.230.247|RU|58310|"TELEPORT" LLC
203.78.202.50|MY|10204|NTT MSC Sdn Bhd
208.53.213.37|US|17203|Beresford Municipal Telephone Company
194.0.104.254|LU|47716|ISIX Communications LLP
194.176.61.172|LT|8764|Telia Lietuva, AB
156.255.162.196|VE|61461|Airtek Solutions C.A.
103.122.8.44|ID|150965|PT BAS Network Indonesia
176.104.180.65|PL|50767|FIBERLINK Sp. z o.o.
138.121.12.172|CO|262191|COLUMBUS NETWORKS COLOMBIA
71.13.176.143|US|30242|SAMSA
2001:4860:4860::8888|CA|15169|Google LLC
2606:4700:4700::1111|US|13335|Cloudflare, Inc.
2001:db8::1||0|
::1||0|
fe80::1||0|
2400:cb00::1|US|0|
2a00:1450:4001:81b::200e|DE|15169|Google LLC
2402:b801:f75c:2500:d4e6:e58f:81bd:59bd|BE|0|
2a02:4780:20:667c:c5e0:1e59:1c6a:2b2c|IN|0|
2a14:67c3:181:177f:e064:f0e:20c8:5b0c|HK|199688|Critical Perfect Ltd
2402:a400:8fc2:97fc:9866:167c:9559:5e74|AU|0|
2001:470:3a1:6ed:37a0:cf13:27c7:746d|CA|6939|Hurricane Electric LLC
2001:67c:17b0:e961:1c6:470b:bb35:512|CH|21436|almanid group GmbH
2a0f:1cc5:61:8ae:8e39:bc0c:9753:5826|HK|208753|Marco d'Angelo
2001:450:5e8:78a:f882:4b4b:3e89:5c5a|US|3549|Level 3 Communications, Inc.
2a10:e042:8dc2:921f:8fcf:3bf7:e5fb:8e67|RU|0|
2402:b801:7409:b940:492a:f85f:b2c0:4f73|BE|0|
2402:b801:9915:cd56:298e:ac1b:897f:d37e|BE|0|
2001:447a:6141:fb4d:8e3d:727e:504d:9dbb|AU|0|
2402:b801:e3cd:ff65:b76b:2e1d:36f1:bfb2|BE|0|
2803:4c38:595f:b35d:30c5:bff6:f710:6082|CH|0|
2a06:9800:eec5:2725:78f5:24fe:f464:c648|GB|0|
2402:b801:5619:574f:c0a:d150:ea74:c150|AU|0|
2402:a400:92a0:c527:8c6:81dd:f707:a6b9|AU|0|
2402:b801:6f13:6075:ec7a:8a5d:bb22:7001|AU|0|
2402:a400:c37f:343d:e454:1e09:550e:2342|BE|0|
2001:43ff:6e2c:7afd:9b47:c5a4:b023:c80d|MU|0|
2a05:d050:b4c0:77c1:3861:d899:a739:4c8e|IE|16509|Amazon.com, Inc.
2a0f:6280:1b2f:1d5e:bf09:f6f:41e:201b|GB|47272|HYEHOST LTD
2402:b801:dd33:c71b:41b:863a:58f:60d4|BE|0|
2402:a400:ce30:441:8540:df79:10fc:24fe|BE|0|
2001:df4:e143:8f53:d8b8:8943:fe7c:a84b|CN|0|
2a07:efc0:887:bdc4:ba0a:cbad:9adb:c0e4|DE|0|
2606:f4c0:4c44:591e:59f4:6acc:7436:97df|AU|16509|Amazon.com, Inc.
2a01:800:5707:1baf:1c2d:1c07:6de4:d420|ES|12430|VODAFONE ESPANA S.A.U.
2404:a140:1a:babc:cafb:f269:8d9a:309e|US|138915|Kaopu Cloud HK Limited
2801:19:4000:60bd:560f:e20e:86c2:f58e|PY|0|
2a06:9801:5f:99e1:6636:f817:3d9f:c810|BE|200282|CIMAX Technologies LLC
2804:1a:902e:3b2f:de52:45ff:51fc:42df|CH|0|
2a0f:1cc1:d1bf:4fa2:de50:a7b7:95e4:be1|GM|0|
2a01:3e7:38b7:869d:b162:59c3:42b4:a9aa|CA|6453|TATA COMMUNICATIONS (AMERICA) INC
2402:a400:f827:a5d9:23d1:f2bc:c81c:b93b|AU|0|
2a03:1c07:58dc:ac5f:e3d0:3744:3516:3c91|BH|0|
2001:470:d809:3d3c:8314:75d9:5771:a078|VE|6939|Hurricane Electric LLC
2001:470:5c13:e4cd:c871:e493:4f6:9a53|SK|6939|Hurricane Electric LLC
2a0a:c184:4bb9:aab8:a89a:e886:2b78:dc38|IT|0|
2a01:53c0:fff9:6a41:7666:57fc:e6f2:d972|GB|54994|Meteverse Limited.
2001:67c:6f3:3ad6:9e6f:eea:db54:ea4|NL|0|
2a0d:d940:b13d:b7ce:8e73:db26:d213:1c47|KP|200954|Andrey Shemanin
2a04:bc40:1dc7:1705:5223:f0ae:f24b:1629|PL|0|
2a05:d050:2088:386b:4064:ac22:d5e:c71b|FR|16509|Amazon.com, Inc.
2a0f:1cc6:bab5:2618:63d7:32a6:bf6b:1db8|DE|204535|Tan Kok Feng
2a07:f8ea:d627:e86d:8e64:769f:8a3a:21be|NL|0|
2a06:ea26:186a:20d4:a1fa:4c6e:6a3e:e6ae|NL|0|
2402:a400:ccca:9cd9:ea5d:57f7:c205:2431|BE|0|
2001:470:7b28:148e:3ddf:e521:5034:6001|US|6939|Hurricane Electric LLC
2a14:3f80:1f68:97f:808b:26f1:2208:6107|GB|0|
2a02:2230:1206:332d:10d0:3bfb:ad8b:74b0|HR|25467|Akton d.o.o.
2001:559:1cb:bca:b752:1d65:f3bd:987e|US|20214|Comcast Cable Communications, LLC
2804:8310:7879:f78a:b8c5:fb5:77f9:5798|BR|272174|JONATAN F DA SILVA SERVICOS - ME
2a13:2044:c826:b4fa:46b3:dd47:6da7:6911|MD|35346|SC ITNS.NET SRL
2a10:51c0:f19d:cba7:eb71:4e70:cfdf:ec20|SG|44364|LVNET LTD
2a03:d007:4ab:ba98:7473:3af1:6049:ee1a|RU|31133|PJSC MegaFon
2806:2f0:7620:32f9:b1bd:5a6d:84ac:21da|MX|17072|TOTAL PLAY TELECOMUNICACIONES, S.A.P.I. DE C.V.
2600:1480:400:4e96:15b7:4a78:2141:73aa|US|21342|Akamai International B.V.
2602:feda:d60:2f96:ddf5:65b3:9e87:7dfb|CA|212034|Zezhu Yu
2403:c00:b03:7c11:ed41:2131:d71f:3645|IN|17488|HATHWAY CABLE AND DATACOM LIMITED
2a12:be07:a712:205c:dc39:60ba:a1ec:3697|UA|49111|iNet Ltd
2a00:1d37:3401:1892:69c:3104:dd7:c68a|TR|47331|TTNet A.S.
2603:c081:8b:ab0b:1bb1:2e34:8db6:31d7|KR|54253|Oracle Corporation
2a12:bec4:156:cf7b:c13f:effd:163a:2dae|EE|218731|Andris Jakovlevs
2402:8100:2055:5e3a:bc10:958b:322:65e3|IN|55410|Vodafone Idea Ltd. (VIL)
2400:cb00:1441:3155:a6ac:7830:fcb5:306a|CA|13335|Cloudflare, Inc.
2a09:b181:4124:4891:3672:f49d:d7fd:2338|UA|56485|TheHost LLC
2602:fa3d:c1:8a57:2d05:162d:9a55:88ec|US|25759|Rozint Ltd Co
2a0d:3dc1:162b:52d7:3e03:540f:6b3a:e4c2|CH|210312|Antonios A. Chariton
2a09:be41:3f60:720:1072:e242:e10c:168e|PT|209968|Kew Solutions Unipessoal Lda
#C|KR|116081260|2628
#C|JP|202964698|10596
#C|SG|20316692|8084
#A|4766|46352224|1563
#A|9318|14544640|649
#A|15169|1295616|121
""".trim()

    @Test fun matchesPythonLookups() {
        var n = 0
        for (line in VECTORS.lines()) {
            if (line.startsWith("#")) continue
            val (ip, cc, asn, name) = line.split('|', limit = 4)
            val r = db.lookup(ip)!!
            assertEquals("$ip 국가", cc.ifEmpty { null }, r.country)
            assertEquals("$ip ASN", asn.toInt().takeIf { it > 0 }, r.asn?.asn)
            if (name.isNotEmpty()) assertEquals("$ip 통신사 이름", name, r.asn!!.name)
            n++
        }
        assertTrue("시험 수 $n", n >= 400)
    }

    @Test fun rangesMatchPythonTotals() {
        for (line in VECTORS.lines().filter { it.startsWith("#") }) {
            val p = line.split('|')
            if (p[0] == "#C") {
                val r = db.countryRanges(p[1])
                assertEquals("${p[1]} 주소 수", p[2].toLong(), r.sumOf { it.second - it.first + 1 }); assertEquals("${p[1]} 범위 수", p[3].toInt(), r.size)
                // 범위의 처음과 끝은 실제로 그 나라
                for ((a, b) in r.take(30)) { assertEquals(p[1], db.country(InetAddress.getByAddress(IpUtil.longToV4(a)))); assertEquals(p[1], db.country(InetAddress.getByAddress(IpUtil.longToV4(b)))) }
            } else {
                val r = db.asnRanges(p[1].toInt())
                assertEquals("AS${p[1]} 주소 수", p[2].toLong(), r.sumOf { it.second - it.first + 1 }); assertEquals("AS${p[1]} 범위 수", p[3].toInt(), r.size)
            }
        }
        assertTrue(db.countryRanges("ZZ").isEmpty() && db.asnRanges(-5).isEmpty())
    }

    @Test fun v4MappedV6AndLookups() {
        assertEquals("US", db.country(InetAddress.getByName("::ffff:8.8.8.8")))
        assertEquals("KR", db.lookup("168.126.63.1")!!.country)
        assertNull(db.lookup("not an ip")); assertEquals("자료 없음", db.lookup("192.168.0.1")!!.countryLabel)
        assertEquals("대한민국 (KR)", db.lookup("210.220.163.82")!!.countryLabel); assertTrue(db.lookup("210.220.163.82")!!.orgLabel.startsWith("AS9318 "))
        assertTrue(db.sourceNote.contains("DB-IP"))
    }

    @Test fun asnNamesAndSearch() {
        assertEquals("Google LLC", db.asnName(15169)); assertNull(db.asnName(99999999))
        val found = db.searchAsn("korea telecom")
        assertTrue(found.any { it.asn == 4766 }); assertTrue(db.searchAsn("AS4766").any { it.asn == 4766 }); assertTrue(db.searchAsn("").isEmpty())
        assertTrue(db.searchAsn("a", 7).size <= 7)
    }

    @Test fun countryNames() {
        assertEquals("대한민국", CountryNames.ko("kr")); assertEquals("XX", CountryNames.ko("XX")); assertEquals("자료 없음", CountryNames.label(null))
        assertEquals("KR", CountryNames.find("한국")); assertEquals("KR", CountryNames.find("kr")); assertEquals("US", CountryNames.find("미국")); assertEquals("JP", CountryNames.find("Japan"))
        assertNull(CountryNames.find("")); assertNull(CountryNames.find("존재하지않는나라"))
        // 자료에 있는 모든 나라 코드에 한국어 이름이 있어야 함
        for (c in db.countryCodes) assertTrue("$c 한국어 이름", CountryNames.isKnown(c))
    }
}
