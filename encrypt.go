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
    "github.com/satori/go.uuid"
    "io/ioutil"
    "log"
    "os"
    "strings"
    "text/template"
)

var dataRaw01 = `
aaa,10,2015-10-29 10:21:35.222,,,
bbb,33,2015-11-10 21:10:02.333,,,
`

var dataTemplate = `
  <data>
    <id>{{.Id}}</id>
    <format>{{.Fmt}}</format>
    <encoding>base64</encoding>
    <data-content>
{{.Content}}
    </data-content>
  </data>`

var docTemplate = `
<doc>
  <signature>
    <digest>SHA1</digest>
    <digest-value-encrypted>{{.DigestVal}}</digest-value-encrypted>
    <sigvalue>{{.SigValue}}</sigvalue>
  </signature>
{{.DataNode}}
</doc>
`

var (
    upsPrivateKeyPath   = "ups_rsa.pem"
    customPublicKeyPath = "mykey.pub"
    storeFile           = "dataSums.store"
)

type SigData struct {
    Sha1Sum, DigestVal, SigValue, DataNode string
}

type BizData struct {
    Id, Fmt, Content string
}

func main() {
    args := os.Args[1:]
    if len(args) < 1 {
        usage()
    }
    dataFile := args[0]

    log.Println("开始加密文件：", dataFile)
    bizData, err := getBizData(dataFile)
    if err != nil {
        log.Fatal(err)
    }
    log.Println("生成文件数据ID：", bizData.Id)

    dataContent := genDataContent(bizData)
    sigData, err := computeSigData(bizData.Content)
    sigData.DataNode = dataContent
    if err != nil {
        log.Fatal(err)
    }
    log.Println("生成文件数据SHA1摘要：", sigData.Sha1Sum)
    log.Println("对SHA1摘要用客户公钥进行RSA加密，生成摘要密文：", sigData.DigestVal)
    log.Println("对摘要密文采用我方私钥做数字签名：", sigData.SigValue)

    doc, err := genDoc(sigData)
    if err != nil {
        log.Fatal(err)
    }

    appendDataRecord(storeFile, bizData.Id, sigData.Sha1Sum)
    log.Println("纪录数据ID和数据摘要到文件成功：", storeFile)

    resf := "M" + parseFileFromPath(dataFile) + ".xml"
    writeToResultFile(resf, &doc)
    log.Println("文件加密成功，结果文件：", resf)
}

func usage() {
    log.Fatalln("usage: " + os.Args[0] + " data-file ")
}

func getBizData(f string) (*BizData, error) {
    id := uuid.NewV4().String()
    dataFmt := "CSV"
    var fbytes []byte
    var err error
    if fbytes, err = ioutil.ReadFile(f); err != nil {
        return nil, err
    }
    fbytes = bytes.TrimSpace(fbytes)

    // TODO: trim each line of data
    fb64 := base64.StdEncoding.EncodeToString(fbytes)
    //log.Println("rawDataB64:", fb64)
    return &BizData{id, dataFmt, fb64}, nil
}

func genDataContent(biz *BizData) string {
    t := template.Must(template.New("dataTemplate").Parse(dataTemplate))
    var buf bytes.Buffer
    err := t.Execute(&buf, *biz)
    if err != nil {
        log.Println(err)
    }

    return buf.String()
}

func computeSigData(s string) (*SigData, error) {
    sha1Sum := sha1.Sum([]byte(s))
    sha1SumB64 := base64.StdEncoding.EncodeToString(sha1Sum[:])

    //log.Println("sha1 digest: ", sha1SumB64)
    digestValEncryptedBs, err := rsaEncrypt(sha1SumB64)
    if err != nil {
        return nil, err
    }
    digestValEncrypted := base64.StdEncoding.EncodeToString(digestValEncryptedBs)
    //log.Println("rsa encrypt result:", digestValEncrypted)

    sigVal, err := signDigestVal(digestValEncrypted)
    if err != nil {
        return nil, err
    }
    return &SigData{Sha1Sum: sha1SumB64, DigestVal: digestValEncrypted,
        SigValue: sigVal, DataNode: ""}, nil
}

func rsaEncrypt(s string) (digEncrypted []byte, err error) {
    var parsePublicKey = func() (*rsa.PublicKey, error) {
        var cusPubKey []byte
        if cusPubKey, err = ioutil.ReadFile(customPublicKeyPath); err != nil {
            return nil, err
        }

        //log.Println("pubkey content: ", cusPubKey)
        block, _ := pem.Decode(cusPubKey)
        //log.Println("block type:", block.Type, "==========", x)
        if block == nil {
            return nil, errors.New("parse public key error: " + customPublicKeyPath)
        }

        pub, err := x509.ParsePKIXPublicKey(block.Bytes)
        if err != nil {
            return nil, err
        }

        switch t := pub.(type) {
        case *rsa.PublicKey:
            return t, nil
        default:
            return nil, errors.New("invalid rsa public key: " + customPublicKeyPath)
        }
    }

    pubKey, err := parsePublicKey()
    if err != nil {
        return nil, err
    }

    return rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(s))
}

func signDigestVal(s string) (sign string, err error) {
    var loadPrivateKey = func() (*rsa.PrivateKey, error) {
        pemBs, err := ioutil.ReadFile(upsPrivateKeyPath)
        if err != nil {
            return nil, err
        }
        block, _ := pem.Decode(pemBs)
        if block == nil {
            return nil, errors.New("decode private key failed:" + upsPrivateKeyPath)
        }
        return x509.ParsePKCS1PrivateKey(block.Bytes)
    }

    priKey, err := loadPrivateKey()
    if err != nil {
        return "", err
    }

    h := sha1.New()
    h.Write([]byte(s))
    d := h.Sum(nil)

    resBs, err := rsa.SignPKCS1v15(rand.Reader, priKey, crypto.SHA1, d)
    resBsB64 := base64.StdEncoding.EncodeToString(resBs)
    return string(resBsB64), err
}

func genDoc(sig *SigData) (doc string, err error) {
    t := template.Must(template.New("dt").Parse(docTemplate))
    var buf bytes.Buffer
    err = t.Execute(&buf, sig)
    return buf.String(), err
}

func writeToResultFile(f string, sp *string) {
    //log.Println("file content: ", *sp, f)
    ioutil.WriteFile(f, []byte(*sp), 0660)
    //log.Println("successful write result to file.")
}

func parseFileFromPath(fpath string) (fname string) {
    ps := strings.Split(fpath, "/")
    fname = ps[len(ps)-1]
    return
}

func appendDataRecord(filename, dataId, sha1Sum string) {
    line := dataId + "," + sha1Sum
    f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil {
        log.Println("add data record error:", err)
    }
    defer f.Close()

    _, err = f.WriteString("\n" + line)
    if err != nil {
        log.Println("write data record error:", err, "\ndata:", line)
    }
}
