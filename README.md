## 安全模块提供了三个程序，分别是：  
* 加密程序 encrypt.go  
* 安全验证以及解密程序 verify-decrypt.go  
* 安全验证服务 verify-server.go  

### 编译运行：
* go build encrypt.go , 得到可执行文件encrypt  
  运行方式： ./encrypt {dataFile}  

* go build verify-decrypt.go , 得到可执行文件verify-decrypt  
  运行方式： ./verify-decrypt {encodedDataFile.xml}  

* go build verify-server.go , 得到可执行文件verify-server  
  运行方式： ./verify-server  

### 加密程序(encrypt.go)步骤:
1. 读入数据文件，给数据文件生成唯一的ID。
2. 生成数据文件的摘要。
3. 对摘要用客户的RSA公钥进行加密操作，生成摘要的密文。(digest-value-encrypted元素的值)
4. 对上一步的摘要密文用我方的RSA私钥做数字签名，生成签名字段。(sigvalue元素的值)
5. 生成结果文件。结果文件的结构如下：
`
<doc>  
  <signature>  
    <digest>SHA1</digest>  
    <digest-value-encrypted>摘要的密文</digest-value-encrypted>  
    <sigvalue>数字签名</sigvalue>  
    </signature>  
    <data>  
      <id>数据文件ID</id>  
      <format>CSV</format>  
      <encoding>base64</encoding>  
      <data-content>数据文件BASE64编码</data-content>  
  </data>  
</doc>  
`

### 安全验证以及解密程序(verify-decrypt.go):  
验证解密步骤：  
1. 用银联智惠公钥来验证数字签名。  
2. 用客户自己的私钥来解密摘要的密文(digest-value-encrypted元素), 得到数据文件摘要D1。  
3. 计算数据文件摘要，得到D2，对比D1和D2，相等说明数据没有被篡改过。  
4. base64解密数据，得到数据文件。  

### 安全验证服务(verify-server.go):  
上传数据文件的ID以及文件内容，验证数据没有被篡改过。  
