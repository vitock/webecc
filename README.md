
# 这是用来做什么的？
定期导出密码管理器的密钥加密备份，发送到邮箱。

> 以前搞丢过bitwarden的两步验证，只能删掉账号。  
> 定期导出管理器的密钥 
> 将公钥放到链接里面，方便每次备份，不用每次输入短语



  
# 带入参数

通过页面的一对密钥对 解密hash里面的data,解密成一个json
```
私钥 yNmVrcoS5D4xMTvjAPSkZe57HZqPZoIUxznm+SqWKFo=
公钥 dTj41nmwoLcguLpM9AntyKgg67xx6K4UAxc27CLIcFw=
```
json结构
```
{
    prefix:string  
    pubkey:string
    toEmail:string
}
```
|字段|说明|其他|
|-|-|-|
|prefix|密码短语的前缀(建议邮箱后面加上`#`)，和密码短语一起生成密钥对|可为空|
|pubkey|传入的默认公钥，用来加密|
|toEmail|生成mailto链接，发送加密的结果作为备份|
|emailSubject|邮件主题|



## 通过hash 带入参数

[https://webecc.pages.dev/#&data=BAAQACAAIAB3v4SZnpkL7YvNQK4Up1anEtK61zy7RWgCxTKz1jpp9oH8QLfqdbqAZRFcNnHvqYHnqfx91GT1hvch7LdnMM6c88W6QV5V56fpWLcXU5jXVWv%2BiZY4P3INk%2FJw6o5NtVJhYTHFK0UcXb7hLdx7GCaTIgWg0Zon3%2B9BIEaspj8c166yRsjD5TeZb5IWUjzPUGaxb1vQ3FCQH%2FRE6MLcf7S2hhMUT2yJzXaoqJIUMOnHtbcPmY4BpN6trjItVlE0rJkZsreBRybrcrMXyzdasklMLpk2LVcY5G4noZDRnY93nESSKkerOv%2Fs4nz82fvJjEzY%2F%2FRcAoy7JP%2BgOlvXSsUp](https://webecc.pages.dev/#&data=BAAQACAAIAB3v4SZnpkL7YvNQK4Up1anEtK61zy7RWgCxTKz1jpp9oH8QLfqdbqAZRFcNnHvqYHnqfx91GT1hvch7LdnMM6c88W6QV5V56fpWLcXU5jXVWv%2BiZY4P3INk%2FJw6o5NtVJhYTHFK0UcXb7hLdx7GCaTIgWg0Zon3%2B9BIEaspj8c166yRsjD5TeZb5IWUjzPUGaxb1vQ3FCQH%2FRE6MLcf7S2hhMUT2yJzXaoqJIUMOnHtbcPmY4BpN6trjItVlE0rJkZsreBRybrcrMXyzdasklMLpk2LVcY5G4noZDRnY93nESSKkerOv%2Fs4nz82fvJjEzY%2F%2FRcAoy7JP%2BgOlvXSsUp)


# 格式说明


## 结构
|2字节|2字节|2字节|2字节|IV|MAC|随机公钥|加密数据|
|-|-|-|-|-|-|-|-|
 
`下面short都是小端模式`

+ 1-2字节short 意义
  - 4：先gzip后加密
  - 5：直接加密

+ 3-4字节的short值表示 iv的长度 ，16  
+ 5-6字节的short值表示 mac校验hash的长度 32
+ 7-8字节 字节表示临时公钥长度 ，32
+ IV   // 随机生成
+ MAC  ，//最后计算生成
+ tmpPubKey //随机生成公钥私钥，私钥(tmpSecKey)使用后丢弃
+ EncryptData


## 过程

```
生成临时公钥私钥 tmpSecKey , tmpPubKey

sharedX（32 byte）= publickKey • tmpSecKey 

buffer[96];
copy sharedX  => buffer[0..31]

/**
* 下面公钥按照小端模式比较，先比较高位置，再比较低位
*/
if tmpPubKey > publickKey  
    copy publickKey => buffer[32...63]
    copy tmpPubKey => buffer[64...95]   
else  
    copy publickKey => buffer[32...63]
    copy tmpPubKey => buffer[64...95]    
end  

利用hash算法 blake2b 生成64字节长度digest
digest = blake2b(buffer)

其中 digest[0..31] 作为 AES-CBC 的密钥 aesKey,使用IV 一起加密密钥生成 加密数据 EncryptData

其中 digest[32,63]作为计算mac的密钥 HKEY，输出32字节数据

也是采用blake2b,指定输出32字节，key = HKEY

mac = blake2b(IV + tmpPubKey + EncryptData)


```

 



# 根据密码短语生成密钥

步骤
1. prefix(如果有) + 密码短语  作为  key  = prefix + phrase
2. PBKDF2(key) 生成32 字作为私钥, secKey = PBKDF2(key)
3. 根据私钥生成 密钥对

PBKDF2 参数

|PBKDF2参数|value|
|-|-|
|salt|The California sea lion (Zalophus californianus) is a coastal species of eared seal native to western North America. It is one of six species of sea lion. Its natural habitat ranges from southeast Alaska to central Mexico, including the Gulf of California. This female sea lion was photographed next to a western gull in Scripps Park in the neighborhood of La Jolla in San Diego, California. [2022-04-07 wikipedia]|
|iteration|123456|
|hash|SHA-256|
|outLen|256bit|
 