package main

import (
    "bytes"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "errors"
    "io/ioutil"
    "log"
    "os"
    "strings"
)

var (
    upsPublicKeyFile = "ups_rsa.pub"
    myPrivateKey     = "mykey.pem"
)

func main() {
    args := os.Args[1:]
    if len(args) < 1 {
        usage()
    }

    recvFile := args[0]

    log.Println("开始解密文件：", recvFile)
    bs, err := ioutil.ReadFile(recvFile)
    if err != nil {
        log.Fatal(err)
    }
    fcontent := string(bs)

    log.Println("开始使用银联智惠的公钥验证其数字签名...")
    if !verifySign(&fcontent) {
        log.Println("验证银联智惠数字签名失败！")
    }
    log.Println("验证银联智惠数字签名成功")

    if !checkDisgestSum(&fcontent) {
        log.Fatal("check digest sum failed.")
        log.Println("摘要验证失败。")
    }
    log.Println("摘要一致，验证数据摘要成功！说明数据没有被篡改过。")

    fname := parseFileFromPath(recvFile)
    resFile := fname + ".encdata"
    err = retrieveDataToFile(&fcontent, resFile)
    if err != nil {
        log.Fatal("get result error.", err)
    }
    log.Println("文件解密成功！结果文件为：", resFile)
}

func usage() {
    log.Fatalln("usage: " + os.Args[0] + " message-file ")
}

func verifySign(fc *string) bool {
    digestValEncrypted := getXmlNodeText("digest-value-encrypted", fc)
    signVal := getXmlNodeText("sigvalue", fc)
    //log.Println("signVal:", signVal)

    pubKey, err := loadUpsPublicKey()
    if err != nil {
        log.Println("Error get public key:", upsPublicKeyFile)
        log.Println(err)
        return false
    }

    dst := make([]byte, base64.StdEncoding.DecodedLen(len(signVal)))
    _, err = base64.StdEncoding.Decode(dst, []byte(signVal))
    if err != nil {
        log.Println("base64 decode error:", err)
        return false
    }

    dst = bytes.Trim(dst, "\x00")
    //log.Println("dst len: ", len(dst), "\n", dst)

    h := sha1.New()
    h.Write([]byte(digestValEncrypted))
    d := h.Sum(nil)
    return rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, d, dst) == nil
}

func checkDisgestSum(fc *string) bool {
    dataStr := getXmlNodeText("data-content", fc)
    dataStr = strings.TrimSpace(dataStr)
    sha1Sum := sha1.Sum([]byte(dataStr))
    sha1SumB64 := base64.StdEncoding.EncodeToString(sha1Sum[:])
    log.Println("计算数据的SHA1摘要为：", sha1SumB64)

    priK, err := loadPrivateKey(myPrivateKey)
    if err != nil {
        log.Println(err)
        return false
    }

    digestRsaEncrypted := getXmlNodeText("digest-value-encrypted", fc)
    signB64Decode := make([]byte, base64.StdEncoding.DecodedLen(len(digestRsaEncrypted)))
    _, err = base64.StdEncoding.Decode(signB64Decode, []byte(digestRsaEncrypted))
    if err != nil {
        log.Println(err)
        log.Println("b64 decode error:", digestRsaEncrypted)
        return false
    }
    signB64Decode = bytes.Trim(signB64Decode, "\x00")

    log.Println("开始用私钥解密摘要密文：", digestRsaEncrypted)
    decryptBs, err := rsa.DecryptPKCS1v15(rand.Reader, priK, signB64Decode)
    if err != nil {
        log.Println(err)
        return false
    }

    decryptStr := string(decryptBs)
    log.Println("摘要解密成功，结果为：", decryptStr)

    return decryptStr == sha1SumB64
}

func retrieveDataToFile(fc *string, resFile string) error {
    dataContent := getXmlNodeText("data-content", fc)
    dataContent = strings.TrimSpace(dataContent)
    dst := make([]byte, base64.StdEncoding.DecodedLen(len(dataContent)))
    _, err := base64.StdEncoding.Decode(dst, []byte(dataContent))

    if err != nil {
        return err
    }
    dst = bytes.Trim(dst, "\x00")
    return ioutil.WriteFile(resFile, dst, 0660)
}

func getXmlNodeText(node string, fc *string) (t string) {
    bgTag := "<" + node + ">"
    endTag := "</" + node + ">"
    beginPos := strings.Index(*fc, bgTag)
    endPos := strings.Index(*fc, endTag)
    if beginPos > 0 && endPos > 0 {
        t = (*fc)[beginPos+len(bgTag) : endPos]
        t = trimStr(t)
    }
    return
}

func getXmlNode(node string, fc *string) string {
    bgTag := "<" + node + ">"
    endTag := "</" + node + ">"
    return bgTag + getXmlNodeText(node, fc) + endTag
}

func trimStr(data string) (s string) {
    s = strings.Replace(data, "\n", "", -1)
    s = strings.Replace(s, "\t", "", -1)
    s = strings.Replace(s, " ", "", -1)
    return
}

func parseFileFromPath(fpath string) (fname string) {
    ps := strings.Split(fpath, "/")
    fname = ps[len(ps)-1]
    return
}

func loadUpsPublicKey() (*rsa.PublicKey, error) {
    pubBytes, err := ioutil.ReadFile(upsPublicKeyFile)
    if err != nil {
        return nil, err
    }

    //log.Println("pubBytes:", pubBytes)

    block, _ := pem.Decode(pubBytes)
    //log.Println("block", block)
    if block == nil {
        return nil, errors.New("parse public key error: " + upsPublicKeyFile)
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    switch t := pub.(type) {
    case *rsa.PublicKey:
        return t, nil
    default:
        return nil, errors.New("invalid public key: " + upsPublicKeyFile)
    }
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
    bs, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(bs)
    if block == nil {
        return nil, errors.New("load private key error." + path)
    }
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}
