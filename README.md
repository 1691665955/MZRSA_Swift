# MZRSA_Swift
MZRSA_Swift是一个轻量级框架，框架功能包含RSA加密/解密Data、RSA加密/解密String，支持字符串密钥和证书密钥

### 公钥加密&私钥解密(字符串密钥)

- 代码示例

```
let PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArdklK4kIsOMuxTZ8jG1PRPfXqSDmaCIQ+xEpIRSssQ6jiuvhYZTMUbV22osgtivuyKdnHm+cvzGuZCSB8QFyCcM7l09HZVs0blLkrBAU5CVSv+6BzPQTVJytoi/VO4mlf6me1Y9bXWrrPw1YtC1mnB2Ix9cuaxOLpucglfGbUaGEigsUZMTD2vuEODN5cJi39ap+G9ILitbrnt+zsW9354pokVnHw4Oq837Fd7ZtP0nAA5F6nE3FNDGQqLy2WYRoKC9clDecD8T933azUD98b5FSUGzIhwiuqHHeylfVbevbBW91Tvg9s7vUMr0Y2YDpEmPAf0q4PlDt8QsjctT9kQIDAQAB"

let PRIVATE_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCt2SUriQiw4y7FNnyMbU9E99epIOZoIhD7ESkhFKyxDqOK6+FhlMxRtXbaiyC2K+7Ip2ceb5y/Ma5kJIHxAXIJwzuXT0dlWzRuUuSsEBTkJVK/7oHM9BNUnK2iL9U7iaV/qZ7Vj1tdaus/DVi0LWacHYjH1y5rE4um5yCV8ZtRoYSKCxRkxMPa+4Q4M3lwmLf1qn4b0guK1uue37Oxb3fnimiRWcfDg6rzfsV3tm0/ScADkXqcTcU0MZCovLZZhGgoL1yUN5wPxP3fdrNQP3xvkVJQbMiHCK6ocd7KV9Vt69sFb3VO+D2zu9QyvRjZgOkSY8B/Srg+UO3xCyNy1P2RAgMBAAECggEAInVN9skcneMJ3DEmkrb/5U2yw2UwBifqcbk/C72LVTTvmZOTgsH5laCARGUbQMCIfeEggVniGcuBI3xQ/TIqJmE6KI2gOyjOxadMiAZP/cCgHEbsF3Gxey3rBKCyhTCNSzaVswLNO0D8C+1bTatKEVuRRvsRykt/fL+HJ/FRteYYO9LuLv2WESJGE6zsi03P6snNiRracvYqz+Rnrvf1Xuyf58wC1C6JSjZ9D6tootPDBTEYaIIbpEnV+qP/3k5OFmA9k4WbkZI6qYzqSK10bTQbjMySbatovnCD/oqIUOHLwZpL051E9lz1ZUnDbrxKwT0BIU7y4DYaHSzrKqRsIQKBgQDTQ9DpiuI+vEj0etgyJgPBtMa7ClTY+iSd0ccgSE9623hi1CHtgWaYp9C4Su1GBRSF0xlQoVTuuKsVhI89far2Z0hR9ULr1J1zugMcNESaBBC17rPoRvXPJT16U920Ntwr00LviZ/DEyvmpVDagYy+mSK0Wq+kH7p5aR5zAHXWrQKBgQDSqQ6TBr5bDMvhpRi94unghiWyYL6srSRV9XjqDpiNU+yFwCLzSG610DyXFa3pV138P+ryunqg1LtKsOOtZJONzbS1paINnwkvfwzMpI7TjCq1+8rxeEhZ3AVmumDtPQK+YfGbxCQ+LAOJZOu8lGv1O7tsbXFp0vh5RmWHWHvy9QKBgCMGPi9JsCJ4cpvdddQyizLk9oFxwAlMxx9G9P08H7kdg4LW6l0Gs+yg/bBf86BFHVbmXW8JoBwHj418sYafO+Wnz8yOna6dTBEwiG13mNvzypVu4nKiuQPDh8Ks/rdu1OeLGbC+nzbnCcMuKw5epee/WYqO8kmCXRbdv4ePTvntAoGBAJYQ9F7saOI3pW2izJNIeE8HgQcnP+2GkeHiMjaaGzZiWJWXH86rBKLkKqV+PhuBr2QorFgpW34CzUER7b7xbOORbHASA/UsG8EIArgtacltimeFbTbC9td8kyRxFOcrlS7GWvUZrq/TbtmLWRtHp/hUitlcxXQbZAIQkfbuo62ZAoGBAKBURvLGM0ethkvUHFyGae2YGG/s+u+EYd2zNba7A6qnfzrlMHVPiPO6lx31+HwhuJ0tBZWMJKhEZ5PWByZzreVKVH5fE5LoQLo+B3VCTyTc1fJ9RKLAPrPqHuvzPHHP/n84XHGeit3e4ytd3Mm/6CNbrg7xux2M4RDQmN//1UOY"

var ss = "fajsdajdadj"
MZLog(ss)
ss = MZRSA.encryptString(ss, publicKey: PUBLIC_KEY)!
MZLog(ss)
ss = MZRSA.decryptString(ss, privateKey: PRIVATE_KEY)!
MZLog(ss)
```

- 运行结果

```
在文件(ViewController.swift)第(198)行
 fajsdajdadj


在文件(ViewController.swift)第(200)行
 Xj2jXTCsipJ3fvOjwS7mFs3xHV7aNmQe7Q0yjPC4Ai5iX6ymkvmQzgr9NlyOQIKq
pUex94ORmT5RuCL8jMt++y/g9NiVuS4mCdlb1m3ZwKyABTXTOxncK4QdFFXwy//F
XjOoNRgniq/RSvdO32qiPNCjGECODPMC4sJDsUkWX9SeeBPGIVqO/yorVD+s5Q1Z
1R6l6ju5u0r4cnBDEibN4/ZNeH9vAy7CwyJuThz2BNPmIedNofbH7c5+BbbxVS4H
2czR2O+uarPEXTZ1cVnCLAs71y1dg80ckqeSAVLBsBB4FcqcPUqCHm9MwatdLW3w
pBsk3WVfCxgMoJpcCzqF5Q==


在文件(ViewController.swift)第(202)行
 fajsdajdadj
```

### 私钥加密&公钥解密(字符串密钥)

- 代码示例

```
var zz = "skmkfmaksfmaksfaadddfasdadfa"
MZLog(zz)
zz = MZRSA.encryptString(zz, privateKey: PRIVATE_KEY)!
MZLog(zz)
zz = MZRSA.decryptString(zz, publicKey: PUBLIC_KEY)!
MZLog(zz)
```

- 运行结果

```
在文件(ViewController.swift)第(205)行
 skmkfmaksfmaksfaadddfasdadfa


在文件(ViewController.swift)第(207)行
 ACj8OCXFLfLWM58we5Vdr1jvWDXbG/X0rm7cG6zoilWjIXXvl5Fj6XNVVpkgpSuh
1vfU85b4RAIWmdBNXfvm4OcyPbNluYKtkFFTKlaZmPb4gm32dkZeGtwDx/NumzCE
mUAOkde0AAlVGM6+u1JJLZmD3FLL7xYdi4d+wuWVuz6WgLFZcqSrn8IVH7+ERI+l
cTGuse6wruv0SIYzzN5YGor3ViXpr2FEuvGryM8W61oPQUiJ6VpKGbR+0Y5Cz3im
ElJ/1549SgDR91LvLG1eQipfJvCxd/3TwCJ2LARB+BGJK6g+gepKSFdJnpeWhQAJ
SE6il79JYl3MUcTRxIT0rg==


在文件(ViewController.swift)第(209)行
 skmkfmaksfmaksfaadddfasdadfa

```

### 公钥加密&私钥解密(证书密钥)
```
var hh = "zwefdewfqfewfe"
MZLog(hh)
hh = MZRSA.encryptString(hh, publicKeyPath: Bundle.main.path(forResource: "public_key", ofType: "der")!)!
MZLog(hh)
hh = MZRSA.decryptString(hh, privateKeyPath: Bundle.main.path(forResource: "private_key", ofType: "p12")!)!
MZLog(hh)
```

### 私钥加密&公钥解密(证书密钥)
```
var kk = "sddskdksflss"
MZLog(kk)
kk = MZRSA.encryptString(kk, privateKeyPath: Bundle.main.path(forResource: "private_key", ofType: "p12")!)!
MZLog(kk)
kk = MZRSA.decryptString(kk, publicKeyPath: Bundle.main.path(forResource: "public_key", ofType: "der")!)!
MZLog(kk)
```