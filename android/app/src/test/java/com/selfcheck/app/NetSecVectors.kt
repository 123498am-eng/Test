package com.selfcheck.app

/* 자동으로 만든 시험 기준값: openssl 3.0 · 파이썬 cryptography · hashlib 로 계산한 값 (직접 만든 구현과 비교용) */
object SecVectors {
    /** (종류, 비밀번호, 솔트, openssl passwd 결과) */
    val crypt = listOf(
        listOf("apr1", "a", "abcdefgh", "\$apr1\$abcdefgh\$G8IsPsylW5ROvIKsQMRG61"),
        listOf("1", "a", "12345678", "\$1\$12345678\$3Uz6TyHSiGZR0yDMOX3jO0"),
        listOf("5", "a", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$mkeIR17jZH2efuGHyAyi7uqPDT/jX1lPmlgvEvcZX1A"),
        listOf("6", "a", "0123456789abcdef", "\$6\$0123456789abcdef\$qn2kMgR/Cs9pZI2hZfok3cbi0oHyRjH7NUyfGhPKp6EBvlZWbL3JMmASYlyEBxhP4jB3zti0119AKDkHdAVHI0"),
        listOf("6", "a", "shortsal", "\$6\$shortsal\$nHkznPKpywik1.4WekhQ/.y28C64k2NccbQ6GacaIeyeng8tvHk/zcD6a8f3GitArLcAIAkDQJ2ihmWmmakDu."),
        listOf("apr1", "secret", "abcdefgh", "\$apr1\$abcdefgh\$h9FWgUz3n9YxylKLlR5SQ/"),
        listOf("1", "secret", "12345678", "\$1\$12345678\$hj0uLpdidjPhbMMZeno8X/"),
        listOf("5", "secret", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$X0ra9qlY7TJaGBDgorLevriQfwysW8fXnbybcO4mF4/"),
        listOf("6", "secret", "0123456789abcdef", "\$6\$0123456789abcdef\$8CGkKDSyVpVlVNcs5PssRw/Tb8EgfecuA6D/zsRQFumJaU.s8KgTWWc2HfgkB7h2n1qIKiJFeSyUFrwvhILXy."),
        listOf("6", "secret", "shortsal", "\$6\$shortsal\$sgDCQodsQZOrB.1kyl6WHgWzcQAYj/rhEVsODp/j/DH53KlRqryMdcgqZUyuzkyw8IBKQtgz9Q7kdoDHhm4fK1"),
        listOf("apr1", "0123456789abcdef", "abcdefgh", "\$apr1\$abcdefgh\$sxHfOFLANAYXeGF./FBFh."),
        listOf("1", "0123456789abcdef", "12345678", "\$1\$12345678\$QzvqVyjsfEisWRspy9tfx1"),
        listOf("5", "0123456789abcdef", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$XFU8mpdpTRVen2.2vz7qzP77Y0jUqUhvxSvn/fsHST5"),
        listOf("6", "0123456789abcdef", "0123456789abcdef", "\$6\$0123456789abcdef\$RETS15GQmQ4OUuxrWwB5ofVV6AIiF0.9Ic/CEkDFCyFfe2zexAEiuEaB16M5HSdJJ/X7oze8lUAUMzefWhDTX0"),
        listOf("6", "0123456789abcdef", "shortsal", "\$6\$shortsal\$nSmRibwLdJEaSPhmrhj1n.Px0TzCbJl/taB2SESSXZCeBw6r5pq1oK2MIKryYcknQNhRAqHTvBXew33tnGHJc0"),
        listOf("apr1", "0123456789abcdefg", "abcdefgh", "\$apr1\$abcdefgh\$1EmOoQBtUQ/xoE6y2eLUr/"),
        listOf("1", "0123456789abcdefg", "12345678", "\$1\$12345678\$QHk3EEhG67cR4Spqkfs1o/"),
        listOf("5", "0123456789abcdefg", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$5OSO5a/XQ3jVy01Ao1kWtP7UxT8zSQqH2D9ge1YE2X8"),
        listOf("6", "0123456789abcdefg", "0123456789abcdef", "\$6\$0123456789abcdef\$xXLDPZ7zEPT9fXel.SC15h91WYISOM66dZBkl5wBEgz6XDz3iWNCEQbrSgl95eAkStoWtlpYxSfn9i59vYXwn/"),
        listOf("6", "0123456789abcdefg", "shortsal", "\$6\$shortsal\$twjDcM7rWibQRD8MJNM866t9LOc56SEmFg0WoHSJZEvDQ1s66Fw.Rbm7vThflM1Ge9Dk4jKxJV38v9Kn4Xt8j."),
        listOf("apr1", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "abcdefgh", "\$apr1\$abcdefgh\$YN5Vq3U1gvn08d1DIKNhV0"),
        listOf("1", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "12345678", "\$1\$12345678\$auuov0fZjdBP3Zw/5G7Lc."),
        listOf("5", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$rXpRZ3zlH/66OxIQVWQ3YRhzRdaAsUZY.Hl.zIsNjT."),
        listOf("6", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "0123456789abcdef", "\$6\$0123456789abcdef\$ILG5uX2r62uBD21Ss0bPd4E/coNAPVqushlfs6LjZ5EzT.20xPL3S4qJ3f8hP7uh.8xw5UBFzO7zjIJvK3NOP0"),
        listOf("6", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "shortsal", "\$6\$shortsal\$seMZha0Gn8M.5uJp0RWKfrWoVhGHdze0mBdyMvPjJXaqJVeQS4I/T5PXCgS0t1.dEwj5gxbmf/Y.EYIi.5vjB1"),
        listOf("apr1", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "abcdefgh", "\$apr1\$abcdefgh\$Tzt0OD6rLaNx7Jwl9nPUA/"),
        listOf("1", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "12345678", "\$1\$12345678\$ExRZOVKFL/5X6ZqhWwtof0"),
        listOf("5", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$y3aH94xQfRB1lqgG0Y9pu/s/lDYIeb5zN8jotyDisN6"),
        listOf("6", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "0123456789abcdef", "\$6\$0123456789abcdef\$nrOLKqHDJmXSCPDJFbGoktMAMiEx90zwXcOOFHEGTA9BvB5S8h9MZgCKycT3uvErxAdsTFHIwdOW7Sm0n7Sfh/"),
        listOf("6", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "shortsal", "\$6\$shortsal\$f6q6Nvk9lXSsR/pWeuhIFEOJblDcTBiJifP1w8aPgMT2eq.ABFe1N8x7NnDOrUZnnd1zNIa9iuVmh7g9ldV2W."),
        listOf("apr1", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "abcdefgh", "\$apr1\$abcdefgh\$xaU0Xntp1MGyA7RZZE2Sm1"),
        listOf("1", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "12345678", "\$1\$12345678\$dneeYmRBvyI.enpfuCMB7."),
        listOf("5", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$M6MaCpb4kDXVecBS7nQeKMuFEewx.g/3654it/0KP39"),
        listOf("6", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "0123456789abcdef", "\$6\$0123456789abcdef\$JlOc7T7ZJFP/d6o/WajjHF6Y7uH8ZLqZidpUP0y.ipJyBVjVElwibPnQ/l7LqiDsHTsZNWXT5JzbIjWMnaGA21"),
        listOf("6", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "shortsal", "\$6\$shortsal\$.4n9tODKUJFlW2OleoN2O7daT1cV/9Ro.rScV5kuus0WhXd0nvUfkAJfe62mSINhK0M.c/BFvWQtrIZU0Ve96."),
        listOf("apr1", "pässwörd한글", "abcdefgh", "\$apr1\$abcdefgh\$aLNy1U2lB1s3k4W2KlrIq0"),
        listOf("1", "pässwörd한글", "12345678", "\$1\$12345678\$5gdMF6jpC6Xo2rSFEdyrt0"),
        listOf("5", "pässwörd한글", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$yEEcWK15g6UgdDC8I8tTwI2Cwda.5MJrZAKFCXe72NC"),
        listOf("6", "pässwörd한글", "0123456789abcdef", "\$6\$0123456789abcdef\$bjbkJ0rKlSoR3fne4sf7H7rKXnyk2AlEbZ3VeGOlPkvRSiix4A2e2BdQTqn34MZZSVRI1TTF7BJlfAg6nTEVf1"),
        listOf("6", "pässwörd한글", "shortsal", "\$6\$shortsal\$7tGxeZvSFMEj1oVGlt8FmYyQ2O09dX2O9Pr2FkD4DwPOIKbBhBMj3WJgf4VfpS/HzVgH6Rx8kNZxM8ddEahzT0"),
        listOf("apr1", "The quick brown fox jumps over the lazy dog", "abcdefgh", "\$apr1\$abcdefgh\$CykBHwA88cqEL7GC1pGCe1"),
        listOf("1", "The quick brown fox jumps over the lazy dog", "12345678", "\$1\$12345678\$Vavii8XFMWbav/omS4rtO0"),
        listOf("5", "The quick brown fox jumps over the lazy dog", "saltsaltsaltsalt", "\$5\$saltsaltsaltsalt\$yx32LOWxRDRiGVIUSTDB9MjYM9tyLmUHtAlyZC4g7p3"),
        listOf("6", "The quick brown fox jumps over the lazy dog", "0123456789abcdef", "\$6\$0123456789abcdef\$WcCwd9N3VvJEv3MUeBwGZuQe24AVXPFBas4bMQ0jbQbGsWUuX9FxGNFyJpcasd13n4CtG8TUuaDgUaxkKnbdB0"),
        listOf("6", "The quick brown fox jumps over the lazy dog", "shortsal", "\$6\$shortsal\$YF8HF/QLv7sWXJ763DLQs60zbhkr9s1txNdN8WZtqfkO.4nCy5yMxToGpf6pE1xbV.x9JdkXrb2d3xO9zzMmJ/"),
    )
    /** (개인키, 상대 공개값, 공유 비밀, 내 공개키) */
    val x25519 = listOf(
        listOf("d1a5ac9a015fac2ef7b341673635512a1511f41fe37d111b267f039eec5d4f58", "9dc02223da426384268a0b489b28b008464099491967f6f0597853e939953ea0", "c816042e55b022d0500993a539a44d82821234b1b4f764b373a3b2fadf055d06", "b94f5e076e3e3510a3b5208d174347693e0339a4a490e7e6b846a5a461ba9330"),
        listOf("6ab9f1eb8f7d3388f4f9d586f66e99fd54080df2c446f0e58668b09c08a16dd0", "bb82030dbc2bcaba32a90bf2e207a84a856fc5f033b77c480836ab6f77f40f19", "6d4c519a08c7786702aa6efed7ca6071769ca5ec7cdf93adc3576fd10c2a2828", "1ee48331a96232e0157c82a4d239ddb3de4c6966bb870fe4823d94934fa6d455"),
        listOf("015f7e6bc5aeaf483724089e9252cc13b50951a6b69412522765cff4d780306e", "6ca202c88e549dff68c09bfafbfc60b2fac074debc1e6777e9ba4b6c703ed114", "09cbad8aa7e6cafb18ddd44c1c0e47d138271ef3a9d8791783ff17dfd0ce665a", "d22c00d81ad7d6588dd1254815d2f8d7d0b445cc269c9f30b1a13f57733b6d57"),
        listOf("2f5052c9fd15b19a18c584d01363568198613f0c34e84409ef7938709a159ec2", "011e39efe22590f4a339ad19cd180f4d855e32feba602d1ec8e154780838c99c", "06664c429de41b38b4c86dbd17c39d701d0b6426cdf770b4296fc2c882fedc69", "2acd400c4b0330c135db12cb5b83c324bc8bcd4294cd8599bee6b05b3661c460"),
        listOf("94091dd64a21ffe94214bc6d17deeb43873a5cf2f0a71b4b5caa9a5c81b6967d", "e9c981a479986215bab0bf6c32efefa14852534b138c3509d8369edd510363da", "84ad0845a0c33821023d1c870c8ac82e417f83f47f98274ce5e67c4468181911", "272d994702df37d6a01dac29baf3065b11f069f5e8e98a90ad3735b4ab29c820"),
    )
    /** (시드, 공개키) */
    val ed25519 = listOf(
        listOf("28554ffdaccebd7ecb9f313a72e272e27fe3f2c7b1d15b1c6a7df5a361769dd8", "8f80338eef733ec67c601349c4a8251393b28deb722cfd0a91907744a26d3dab"),
        listOf("df9ecf4c79e5ad77701cfc88c196632b353149d85810a381f469f8fc05dc1b92", "cc1983469486418cd66dcdc8664677c263487b736840cfd1532e144386fa7610"),
        listOf("35b0fad16758b58124f39f00d26061704514be4e39c1e03b7b23534afd6081e3", "88166617f91bc145b243c2ae6e1088f1208bf17311cca74dbf032fee25b219e0"),
        listOf("b9e1e9b068c94af0129d20f775a395e4e0ab28cd2026f45eea0821b72bf58d93", "6f97404947a00311785785217b1759b002cbae16da26e0801f0dcbe4e00d5f45"),
        listOf("13e5c80a2cb759451513d80f7944f1fd979af53f95efeeaf8decfc9c66481dab", "fb7a8589cbe59427b2e9c91a5091bf43cf2080f1d4f1947af0d214ca825076f0"),
        listOf("beb441370ff9b72d8e542ced70a0bf8caa1c7400862e940dbb7dc591d9380406", "30da57cda802def8dfd764812f2e3c82eb2871b2a14e3bb634f2195ef733796d"),
    )
    /** (이름, 공개키 한 줄, SHA256 지문, MD5 지문) */
    val ssh = listOf(
        listOf("ed25519", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlpqEX4l2s/wUMBm7wKQ7eDVeIY1pRPF198NqSxPNaB me@host", "SHA256:N1VHpSmBUOYjpdQ3HPCnZQkuCtpfAEihjKOHGDDpIBg", "MD5:af:67:64:40:6c:64:ab:2d:01:a7:68:d4:83:ec:06:25"),
        listOf("rsa2048", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3IdyeWljnrGGa2fmCqfsB/srXWmGTztjg6dyabWBduRD/DQIzrQWC2jvJ+XB8bGag74GeCKT8gbztN54vhKtgXvzBIsJFC934zu0g274zYARCyCFCahPsjmu2/bw2CFzeNM33tuc9ksBUkYXWtfVGYzv7QGshTXy1oTVG+n3FT9cPfYXVPh1QbFFN20lCQDhVD2DQpIRijblarAN5XNuB45JzlcbIxLsrT6D5u4HkkFXKX+mMwg9aMKdv1nUISjZSMDxp2yuLX87t81vtqENJfmXhirPn7KGc+YueW7WICZHHL4FHysFUw31SEKN8ozCO/IMhH/LbVb1r/x0R5k29 me@host", "SHA256:PlCZxxPSM2CUNY728dLA0Dzfsvr02nft9dotjtZIppI", "MD5:8b:02:31:ac:46:96:a2:69:a8:6a:d8:2b:30:a8:2b:f4"),
        listOf("rsa1024", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCp7HkC4mdD6atVmc0aIkfg5fTPh4m9CYP4nqzfmhW2opmx8uAOh6j+mHyuTpsiNzqE4SfQnD7Fue+4HP/aojZkc16w5HLzin0fZ/6ezNl4RNExQBiJsjSMbEacGoHTRP+aBIKgW9nsqhJAg36ikuyMjYEE1B5JKpYV/N3SSgqcRQ== me@host", "SHA256:tCxwPsyXxg8cOeRnDd84qyJ6iwOJ5Ri33Sk7y77uTH0", "MD5:a3:4c:7c:53:b6:a9:a1:b3:b5:b3:c7:0c:0b:18:8b:ba"),
        listOf("p256", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNg5PIN8mwIMrnZCyEeaDD5gJQC0MT+p13N+cM2tdiynyvcR7t9HJuQmMOk5YTdV/i9djUh7zrvIH69eZSWCMCc= me@host", "SHA256:xg1NHWeCmWxcgVkg0MRb3ojzJutEwM10wqyVEzHk6/w", "MD5:04:7e:51:75:4d:59:04:d2:df:fc:9f:c7:f5:24:86:0e"),
        listOf("p384", "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBFk+pyLD0Q4RDZZrKzhd2YynGL3ai0V1DPj1qay+IeoQWMmrZGuOP+sZ980gB8CaGq6rEMrYaw4anoD5WGajco6MU1V3WODJHyTDva7cGwFNes3sPwtIgacy7J7vKWIkYA== me@host", "SHA256:C1AO25xpUODjRtsUVg4abQXhWRuvRXOIzmuE72hkQCc", "MD5:f4:db:54:3a:28:d3:78:1b:43:c8:45:23:0a:b7:10:2c"),
    )
    /** (비밀번호, 반복, 암호문) */
    val gcm = listOf(
        listOf("correct horse", "1000", "scbox1.1000.AAECAwQFBgcICQoLDA0ODw.ZGVmZ2hpamtsbW5v.VOl32mlQC-B4NAdTli6U2tLd7Ai3AXEupM2tukhRdHeTacOHa2jw3D6vQwqQQg"),
    )
    /** (비밀번호, 반복, 솔트 16진수, 암호문 Base64) */
    val cbc = listOf(
        listOf("correct horse", "1234", "0102030405060708", "2h03kJr+csLtzbDADI/g6G3Kup/yfqvXyXNq2+DF4dA="),
    )
    /** (해시, 비밀번호 16진수, 솔트 16진수, 반복, 길이, 결과 16진수) */
    val pbkdf2 = listOf(
        listOf("sha256", "70617373776f7264", "73616c74", "1", "32", "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
        listOf("sha256", "70617373776f7264", "73616c74", "4096", "32", "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
        listOf("sha512", "70617373776f7264", "73616c74", "2", "64", "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"),
        listOf("sha1", "", "73616c74", "3", "20", "0cebfb1825d38ce91db4a69a0b9e776b2a2323eb"),
        listOf("sha256", "ed959ceab88020ebb984ebb288", "00ff10", "777", "40", "5f348642d99dfd3abb934f1eefaa817bc29eb7deac608844166eab45b2e9facbf9a7c558b39fdd49"),
    )
    /** (알고리즘, 비밀키, 토큰) */
    val jwtHs = listOf(
        listOf("HS256", "super-secret-key", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.QHrOEAfJwnNbAArliVrI85uWlvU3DCLdH6T998IUHK4"),
        listOf("HS384", "super-secret-key", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.TpNkW9Y8x95yHGE1UsTQ7QpbR0mFqcFPgIU57MHF7ZyYatiDxdWkCrJG54mgLToO"),
        listOf("HS512", "super-secret-key", "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.yOXmQvN5cELmtfr4lFrdEZwqkUoKV55iJ1KS4tCe4dikVljnw0Ur63fp9U7KASoRXP_VIoKqwtWu-SpKnwvMbw"),
    )
    /** (알고리즘, 토큰) */
    val jwtRs = listOf(
        listOf("RS256", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.fdLwn2Ze6hkktTDhiDXDRoTkWVuQPPnF3ZVDhXxLS52Sj85lwmcBjVWTBDreYw_kg4MPHu5jmqw7LBd4Xo2sX1f74jmQxJspWJbMy_1u4LeoJ1YhYTiMtfbO9lTy-maDbplTqDMs6UrRjyQ3tph_u89bVfx_vDVqUCBxjiEGLZ1JN3p1WGeuHD1BB740naRWfOWEV_vddHONo41Xij6TGh17Qawi5vgO3hSfeiGFUMapPoSihpn5a3HONsXqaf1GuB1Dulg-jEmVJV21W3GlDeSKDqmBLStY9Paf_zyixyNBXWg3Oz6Gu84w5myohGexQHb1SyaBfYAb4LBAAM5afQ"),
        listOf("RS384", "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.LPM6AvvEUPDjPgw_f43pRXGU2tXCEdtsFAzy-_1VlDTMwFhd6hZuywv6MQuqR2Ndqr5VEV2sdqvoa8gknQ7aRAhFIo-XlRrDAFsu_cdOE2uuY7s0xnaIJIB7qy0LLwtqc-JfTfmX4Y6xZGbq9CN4IPDIaCHjInlVaLzJo6_WFN_VsLc0tvQfILGNsKyzGYiDuCVuNB6Xl-BbNDKAHs6zUitHDCA6gu13DRKyG3tGRaJ0__J_aajh_0iFNPWd0tegeFAHyr8mW5trjtqpzS98x050_sIr_rrLWhtgwF_HtRtGgggP_Wsg8xH6hOR7EShov39RP-afyUCeHZOc95dRdQ"),
    )
    val rsaPem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkzG8DGCYuhHLsRSQEBVF\nAORO9/I1iA12dq4iIQNfEG7UZNgOYsopjQ6DwVIOw+hxKQkW4epoGSXffxdrH+OP\nmQdSwmc8SfygDq/PAVKzxhrjIT3TUpFt+usk10UnbUMUWOpJwaFqgMfpS0v4vQFU\nT3yFSdcgiFRcuE9TSsklyqhmjqrX5nJWASlzICASRz4827gq3Dmg4OlupvqBa7Cc\nDUBw9FXUW2E+pYQ4uqsPv15udtf6i+B4N8GGS1XPyRdeu66PMVCTlhzlyu3JChRw\nWpSPuJdus3M6Zu1Nwr4aeuowc/2Ghelh0ZvgiI5YtG2fCwwT9cjlYLrkyGiSHjXH\noQIDAQAB\n-----END PUBLIC KEY-----\n"
    val rsaJwk = "{\"kty\": \"RSA\", \"n\": \"kzG8DGCYuhHLsRSQEBVFAORO9_I1iA12dq4iIQNfEG7UZNgOYsopjQ6DwVIOw-hxKQkW4epoGSXffxdrH-OPmQdSwmc8SfygDq_PAVKzxhrjIT3TUpFt-usk10UnbUMUWOpJwaFqgMfpS0v4vQFUT3yFSdcgiFRcuE9TSsklyqhmjqrX5nJWASlzICASRz4827gq3Dmg4OlupvqBa7CcDUBw9FXUW2E-pYQ4uqsPv15udtf6i-B4N8GGS1XPyRdeu66PMVCTlhzlyu3JChRwWpSPuJdus3M6Zu1Nwr4aeuowc_2Ghelh0ZvgiI5YtG2fCwwT9cjlYLrkyGiSHjXHoQ\", \"e\": \"AQAB\"}"
    /** (알고리즘, 토큰, JWK, PEM) */
    val jwtEs = listOf(
        listOf("ES256", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.a0OpNqFwc98gGwQ1SPGlwEA3B0VheUVPLNm0KdMCs94e7tAZiBR2EGrfIUKY58lFB_pdbd6Yy6dNr9d7cBbErA", "{\"kty\": \"EC\", \"crv\": \"P-256\", \"x\": \"f31D7ox968sF92qutzMST1Icr0xxLp-qH0mjGyqK6JA\", \"y\": \"PBGe7v-duRBL-YOBzKk0h5PtMfjJbgNwNWBTGDuc_Y0\"}", "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf31D7ox968sF92qutzMST1Icr0xx\nLp+qH0mjGyqK6JA8EZ7u/525EEv5g4HMqTSHk+0x+MluA3A1YFMYO5z9jQ==\n-----END PUBLIC KEY-----\n"),
        listOf("ES384", "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.t9n3isn-aU6IkxNGVYmBiwBY028aO42HdRVwNnASs1t2pbPAxK3EDOhVPdEn93Hk5nM-Hz6b7cogSHWxZsl2XMQAKg30P5fuEFw7HZvvbqkrYg8a1Eu67-9N122BpjrP", "{\"kty\": \"EC\", \"crv\": \"P-384\", \"x\": \"GNLtVPTdoujRBhpfFQlKKBxN-yEvxzZF6-Z2vyzm89UrWRVULFPsqJRTh8dKCvTM\", \"y\": \"XMGLDUOksY1y1GCU4jxZ8IlBo1oX1-gOTxr1JXEC-yKCJoOA4ko9tE8Xctw68GKJ\"}", "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGNLtVPTdoujRBhpfFQlKKBxN+yEvxzZF\n6+Z2vyzm89UrWRVULFPsqJRTh8dKCvTMXMGLDUOksY1y1GCU4jxZ8IlBo1oX1+gO\nTxr1JXEC+yKCJoOA4ko9tE8Xctw68GKJ\n-----END PUBLIC KEY-----\n"),
        listOf("ES512", "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6NDEwMjQ0NDgwMH0.AWKt7KWloO_JBHPSD5nXNF8jWrpl6UCJRp30Lh--EEAgvsaz3dcbjfEp8SNs-4aAOLzZnaThI0RoiJtSCJXiU6uQADa8vDMgq5HcBXAg4InuEqx_pBCxJ7h3wYnWQP2jnP4i3-PRrKW5cC9J3AcBYi6m2SZNaAs7TQ4130p9Z7L4Zdle", "{\"kty\": \"EC\", \"crv\": \"P-521\", \"x\": \"AGIMYVamXQDSUsvgR9dXs-jANpWlVA5FT70P02ADQKMOmeaL5BQhyU-131oi9OIsqgx1LE8JTyimHuIvTz6PSmye\", \"y\": \"ARK67o3A-6VEmvkyWdYvsDAWOUY33e__LoHYGyYE8uCPGifkLxeEBa37Dt-T0zXl6SKIfmqGJBE-14HXCB6snTRI\"}", "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAYgxhVqZdANJSy+BH11ez6MA2laVU\nDkVPvQ/TYANAow6Z5ovkFCHJT7XfWiL04iyqDHUsTwlPKKYe4i9PPo9KbJ4BErru\njcD7pUSa+TJZ1i+wMBY5Rjfd7/8ugdgbJgTy4I8aJ+QvF4QFrfsO35PTNeXpIoh+\naoYkET7XgdcIHqydNEg=\n-----END PUBLIC KEY-----\n"),
    )
    const val RFC7748_SCALAR = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    const val RFC7748_U = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
    const val RFC7748_OUT = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    const val ALICE_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    const val BOB_PRIV = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    const val ALICE_PUB = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    const val BOB_PUB = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    const val DH_SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    const val RFC8032_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    const val RFC8032_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    const val WPA_IEEE = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    const val WPA_IEEE2 = "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"
    const val WPA_LONG = "2d43d0dabfdd635377172efa1fc4b4b87dbfc4219193909ded9a7cfb89a3097b"
}
