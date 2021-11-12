Running log on the Azure VM

1. Deploy to Azure VM including vcruntime140.dll which is available `C:\Windows\System32\vcruntime140.dll`

```
C:\Users\azureuser\testCurl>dir
 Volume in drive C is Windows
 Volume Serial Number is C233-0B16

 Directory of C:\Users\azureuser\testCurl

09/13/2021  02:33 AM    <DIR>          .
09/13/2021  02:33 AM    <DIR>          ..
09/13/2021  02:08 AM           702,976 testCurl.exe
07/27/2021  04:54 PM            97,160 vcruntime140.dll
               2 File(s)        800,136 bytes
               2 Dir(s)  110,003,105,792 bytes free
```

2. Run
```
C:\Users\azureuser\testCurl>testCurl.exe
1680 bytes retrieved

{
  "access_token":"xxx",
  "client_id":"2084ae4a-2cb6-495c-8892-e8c5f942cad1",
  "expires_in":"86400",
  "expires_on":"1631586810",
  "ext_expires_in":"86399",
  "not_before":"1631500110",
  "resource":"https://managedhsm.azure.net",
  "token_type":"Bearer"
}

```

3. The access token could be parsed at https://jwt.io
```
 "aud": "https://managedhsm.azure.net",
 "xms_mirid": "/subscriptions/<sub>/resourcegroups/ContosoResourceGroup/providers/Microsoft.Compute/virtualMachines/testvmmhsm"
```

```
E:\>git clone https://github.com/Microsoft/vcpkg.git
E:\vcpkg>bootstrap-vcpkg.bat
E:\vcpkg>vcpkg.exe integrate install
E:\vcpkg>vcpkg install json-c:x64-windows-static
E:\vcpkg>vcpkg install curl:x64-windows-static

E:\vcpkg\packages>dir
 Volume in drive E is Data
 Volume Serial Number is 3800-558E

 Directory of E:\vcpkg\packages

10/03/2021  04:53 PM    <DIR>          .
10/03/2021  04:53 PM    <DIR>          ..
10/03/2021  04:14 PM    <DIR>          cpp-base64_x64-windows-static
10/03/2021  04:14 PM    <DIR>          cpp-base64_x86-windows
10/03/2021  01:39 PM    <DIR>          curl_x64-windows-static
10/03/2021  12:50 PM    <DIR>          curl_x86-windows
10/03/2021  12:58 PM    <DIR>          curl_x86-windows-static
10/03/2021  12:49 PM    <DIR>          detect_compiler_x64-windows
10/03/2021  04:53 PM    <DIR>          detect_compiler_x64-windows-static
10/03/2021  04:14 PM    <DIR>          detect_compiler_x86-windows
10/03/2021  01:09 PM    <DIR>          detect_compiler_x86-windows-static
10/03/2021  01:37 PM    <DIR>          json-c_x64-windows-static
10/03/2021  12:45 PM    <DIR>          json-c_x86-windows
10/03/2021  01:09 PM    <DIR>          json-c_x86-windows-static
10/03/2021  04:56 PM    <DIR>          openssl_x64-windows-static
10/03/2021  12:49 PM    <DIR>          vcpkg-cmake-config_x64-windows
10/03/2021  12:49 PM    <DIR>          vcpkg-cmake_x64-windows
10/03/2021  01:38 PM    <DIR>          zlib_x64-windows-static
10/03/2021  12:49 PM    <DIR>          zlib_x86-windows
10/03/2021  12:56 PM    <DIR>          zlib_x86-windows-static

```
running log
```
C:\Users\azureuser\testCurl>testCurl.exe
jobj from str:
---
{
  "access_token": "---------",
  "client_id": "2084ae4a-2cb6-495c-8892-e8c5f942cad1",
  "expires_in": "85012",
  "expires_on": "1633406238",
  "ext_expires_in": "86399",
  "not_before": "1633319538",
  "resource": "https:\/\/managedhsm.azure.net",
  "token_type": "Bearer"
}
---
access token: 1448, ---

jobj from str:
---
{
  "alg": "RSA1_5",
  "kid": "https:\/\/az400popmhsm.managedhsm.azure.net\/keys\/mypemrsakey\/37c3504320c20b443ac8efe52a530b27",
  "value": "kNXtJ5eTuNmeiFaPAYyId0d15eqTC3Ou_BnAPUKIz2YqfnEeaGE87iR8ID4aB2bVVkBxfFha0fhk_l1RuNXSr-CO-cBOP0tj-UsydD9nn97JUCM3PJ-18ndSG2GZdVnWkxsWUpyMFjGOfZ-3KC6HITV2om1rGplZb426O2LpqaCpBJft3CjlpTsvie_EUc9QaEMID93twDWVeEGliezypG4iSB84UZozKLSP4nVo-neXkRRRTX1xYzcAp9zs9fzljHO5hjlLZvMGe8BsIekvtneBYyyGHwtKDHPTdFlOLT3j0touwfqg2FirmIHVZl7xfl5i4BxHGhNvZ9oGDFegvA"
}
---
value[342] from json kNXtJ5eTuNmeiFaPAYyId0d15eqTC3Ou_BnAPUKIz2YqfnEeaGE87iR8ID4aB2bVVkBxfFha0fhk_l1RuNXSr-CO-cBOP0tj-UsydD9nn97JUCM3PJ-18ndSG2GZdVnWkxsWUpyMFjGOfZ-3KC6HITV2om1rGplZb426O2LpqaCpBJft3CjlpTsvie_EUc9QaEMID93twDWVeEGliezypG4iSB84UZozKLSP4nVo-neXkRRRTX1xYzcAp9zs9fzljHO5hjlLZvMGe8BsIekvtneBYyyGHwtKDHPTdFlOLT3j0touwfqg2FirmIHVZl7xfl5i4BxHGhNvZ9oGDFegvA
input len= 342
output len= 256
decode size 256
input len= 342
output len= 256

90D5ED279793B8D99E88568F018C88774775E5EA930B73AEFC19C03D4288CF662A7E711E68613CEE247C203E1A0766D55640717C585AD1F864FE5D51B8D5D2AFE08EF9C04E3F4B63F94B32743F679FDEC95023373C9FB5F277521B61997559D6931B16529C8C16318E7D9FB7282E87213576A26D6B1A99596F8DBA3B62E9A9A0A90497EDDC28E5A53B2F89EFC451CF506843080FDDEDC035957841A589ECF2A46E22481F38519A3328B48FE27568FA77979114514D7D71633700A7DCECF5FCE58C73B986394B66F3067BC06C21E92FB67781632C861F0B4A0C73D374594E2D3DE3D2DA2EC1FAA0D858AB9881D5665EF17E5E62E01C471A136F67DA060C57A0BC
encode size 342

kNXtJ5eTuNmeiFaPAYyId0d15eqTC3Ou_BnAPUKIz2YqfnEeaGE87iR8ID4aB2bVVkBxfFha0fhk_l1RuNXSr-CO-cBOP0tj-UsydD9nn97JUCM3PJ-18ndSG2GZdVnWkxsWUpyMFjGOfZ-3KC6HITV2om1rGplZb426O2LpqaCpBJft3CjlpTsvie_EUc9QaEMID93twDWVeEGliezypG4iSB84UZozKLSP4nVo-neXkRRRTX1xYzcAp9zs9fzljHO5hjlLZvMGe8BsIekvtneBYyyGHwtKDHPTdFlOLT3j0touwfqg2FirmIHVZl7xfl5i4BxHGhNvZ9oGDFegvA
jobj from str:
---
{
  "alg": "RSA1_5",
  "kid": "https:\/\/az400popmhsm.managedhsm.azure.net\/keys\/mypemrsakey\/37c3504320c20b443ac8efe52a530b27",
  "value": "abcd"
}
---
value from json abcd
```
