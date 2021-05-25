# JWT-Key-Recovery
A tool that recovers the public key used to sign JWT tokens

## Supported algorithms

The following algorithms require two JWT tokens :
- RS256
- RS384
- RS152

The following algorithms require only one JWT token, but give better results with two :

- ES256
- ES384
- ES512

## Requirements

```
python3 -m pip install -r requirements.txt
```

## Usage

```
./recover.py --help
```

All example tokens were generated using https://jwt.io.
### Example RS256

JWT 1 :
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA
```

JWT 2 :
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkVOT0VOVCIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.Yo1R0Gf7JriA9xMHQhT_JjV7X0Y-Y7ZHHH0pYHp-YqrxQCecQ5qyHD8VEqOCMICAo1Ee7BIzYI4DqdUmfH0S_hFEY24_ME3sFX0viMj1El0ZEC7R4tn1W0-bJWsWQNFPU50kheURle2AstYkyo7dncl3DJzW12QbWeUj8PTaNeKfSDcEn2yHtV3_o6j4MZXzWPDTAGlnEbw29ynXsAJusEtKpzIC-J-e3-0AX1bOtN9-b3fy-TSbQfpM2IbExk1ECl2IngMeBiZi5Zrf9_hRAn31LfEN5-SRJQ_Z_ZCblD9wrRogVUuoLJscicDb92U5xrOfJLM277DXu-htyQCIyA
```

Recover the public key :
```
./recover.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkVOT0VOVCIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.Yo1R0Gf7JriA9xMHQhT_JjV7X0Y-Y7ZHHH0pYHp-YqrxQCecQ5qyHD8VEqOCMICAo1Ee7BIzYI4DqdUmfH0S_hFEY24_ME3sFX0viMj1El0ZEC7R4tn1W0-bJWsWQNFPU50kheURle2AstYkyo7dncl3DJzW12QbWeUj8PTaNeKfSDcEn2yHtV3_o6j4MZXzWPDTAGlnEbw29ynXsAJusEtKpzIC-J-e3-0AX1bOtN9-b3fy-TSbQfpM2IbExk1ECl2IngMeBiZi5Zrf9_hRAn31LfEN5-SRJQ_Z_ZCblD9wrRogVUuoLJscicDb92U5xrOfJLM277DXu-htyQCIyA
Recovering public key for algorithm RS256...
Found public RSA key !
n=20101790993208644745807976729182597941929355612162354360099435269825087678371993244844234893013558555686015831335725398637423399304205115261083991022355813201997154499053064318477614909646953959855907663206692927300016800053636628573275271404089122405985685162285559162700174320318326821436949689956974724260182115938767812249391575639780973664572557729842107578524708525191776956150194917696738395922018602710772475751229671360413648976296942707837850780316509559008920087532825564663621482064344153450826739561548502662708814824842358869389530164169290288156380027449103702069177196558531588515097343487007237750067
e=65537
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----
```

### Example ES256 with 2 keys

JWT 1 :
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3MjAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyfQ.H8VTTQMtuf-aexINRZ3J0ikyFwgBp0l-9nrGkFk1vPIUTjM_xnFQsM4JPJVpNTQZZQdsUj9SGl-KVjDb-x6N-Q
```

JWT 2 :
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyfQ.sFLNApKrFRJmHSPsb7-TT5qAXCLdiWSIb7uB9ZZBpuguNY075oA_vGC4sVp3wgFwOU4jpf629GFqIW8dQzrAFw
```

Recover the public key :
```
./recover.py eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3MjAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyfQ.H8VTTQMtuf-aexINRZ3J0ikyFwgBp0l-9nrGkFk1vPIUTjM_xnFQsM4JPJVpNTQZZQdsUj9SGl-KVjDb-x6N-Q eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyfQ.sFLNApKrFRJmHSPsb7-TT5qAXCLdiWSIb7uB9ZZBpuguNY075oA_vGC4sVp3wgFwOU4jpf629GFqIW8dQzrAFw
Recovering public key for algorithm ES256...
Found public ECDSA key !
x=7850540730117855537377310150564140534713067357541121232721010766305002029006
y=65316312644653463644210322201871599477553959356638327946530363791985981247174
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----
```

### Example ES512 with 1 key

JWT :
```
eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AO5vydT7kqcOeTPKcgTeJuWlUhnXWbVUmMWsHVX2ZaVZXoDfqz-Dl7A6LwBcgLfjf24-J-lgey60M744ntaT3klIARDXfI5BRRIC8Blsr5CWwUw_zGDJWMFIVDWFrHcL19ZXSII3CbTlKQiOR0j4VKdsU9U6ucmfbf32KDbTZaAXiOlK
```

Recover the public key :
```
./recover.py eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AO5vydT7kqcOeTPKcgTeJuWlUhnXWbVUmMWsHVX2ZaVZXoDfqz-Dl7A6LwBcgLfjf24-J-lgey60M744ntaT3klIARDXfI5BRRIC8Blsr5CWwUw_zGDJWMFIVDWFrHcL19ZXSII3CbTlKQiOR0j4VKdsU9U6ucmfbf32KDbTZaAXiOlK
Recovering public key for algorithm ES512...
There are 2 public keys that can produce this signature.
As it's not possible to know which one was used, both are displayed below.
Found 2 public ECDSA keys !
x=5172796663093187482850050145915870008996347645873736692097159452129856129580682525658145604549244077699897287381323414601604867557471292917702452564508582700
y=1846833050512987366215853238795224527974188915132287367985929033638992777726736470255361565751181343033676537352827681177147360539089794295589536212782511739
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----

x=4304890414218510640623233278819258871086727635239816549872025481799602436706253601488654553755754162025564959362563998771394280726642811231678590022032953807
y=6286376103176796595243885549212646568265950319693269612297746713552186257890887615522396917756912578661874335023727679252261555093875847064250774965541967997
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBQRLKBxOgCgEXYMV4yz+QpI47IvgB
AfoS69YSHso74PNuL1G3q/0GZeUpPkMYSITkPaAiyy8d4z8sAVISbZ2CEc8B1Nv+
UtVTNjFNMh3TqsE6JDp+BhyFjy6jBhvfYe0J1N/OzR2GN0Tq4CvFr8daBqnA907s
2lbRPtC3AKAMtmMQmH0=
-----END PUBLIC KEY-----
```

