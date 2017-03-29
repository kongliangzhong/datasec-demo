package main

import (
    "bufio"
    "bytes"
    "crypto/sha1"
    "encoding/base64"
    "errors"
    "html/template"
    "log"
    "net/http"
    "os"
    "strings"
)

var DataFile = "dataSums.store"
var MaxFileSize = 32 << 20

type CheckResult struct {
    Id, CheckRes string
}

type BizData struct {
    Id, Fmt, Content string
}

func main() {
    // TODO: add login/register module.
    log.Println("server started.")
    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/checksum", checkSumHandler)
    //http.HandleFunc("/register/", Handler)
    http.ListenAndServe(":8080", nil)
}

func init() {
    // TODO: load dataFile to map
}

var indexPage = `
<html>
  <head>
  <style>
  .outer {
    width: 65%;
    min-width: 600px;
    min-height: 500px;
    background: #CCECF1;
    position:relative
  }
  </style>
  <head>
  <body>
  <div class="outer">
    <div style="height:30px"></div>
    <h2 style="text-align: center">银联智慧数据验证平台</h2>
    <div>
      <form action="/checksum" method="POST" enctype="multipart/form-data">
        <fieldset style="border-bottom: navajowhite;">
        <div style="height:8px"></div>
        <div>
          <label for="dataId">Data Id:</label>
          <input id="dataId" name="dataId" type="text" size="50" maxlength="48"/>
        </div>
        <div style="height:20px"></div>
        <div>
          <label for="dataFile">上传数据文件:</label>
          <input id="dataFile" name="dataFile" type="file"/>
        </div>
        <div style="height:10px"></div>
        </fieldset>
        <fieldset>
        <div>
          <input type="submit" value="提交">
        </div>
        </fieldset>
      </form>
    <div>
  </div>
  </body>
</html>
`

func homeHandler(w http.ResponseWriter, r *http.Request) {
    t, _ := template.New("home").Parse("{{.}}")
    err := t.Execute(w, template.HTML(indexPage))
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

func checkSumHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseMultipartForm(int64(MaxFileSize)) // 32M
    dataId := r.FormValue("dataId")
    log.Println("开始校验数据完整性，数据ID:", dataId)
    file, _, err := r.FormFile("dataFile")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer file.Close()

    data := make([]byte, MaxFileSize)
    count, err := file.Read(data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    data = data[:count]
    checkRes := checkDataSum(dataId, data)
    log.Println("校验结果：", checkRes)

    t, _ := template.New("res").Parse(
        `<html>
         <body>
         <h2>数据校验结果</h2>
         <div>
           <p>Data Id：&nbsp;&nbsp;{{.Id}}</p>
           <p>校验结果：{{.CheckRes}}</p>
         </div>
         <div style="height: 10px;"></div>
         <div><a href="/"><b>返回首页</b></a><div>
         </body>
         </html>
    `)

    err = t.Execute(w, &CheckResult{dataId, checkRes})
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

func checkDataSum(id string, data []byte) string {
    data = bytes.TrimSpace(data)
    dataB64 := base64.StdEncoding.EncodeToString(data)
    //log.Println("dataB64:\n", dataB64)
    sha1Sum := sha1.Sum([]byte(dataB64))
    sha1SumB64 := base64.StdEncoding.EncodeToString(sha1Sum[:])

    sha1SumFromStore, err := getSumFromStore(id)
    if err != nil {
        log.Println("get sum from store file error:", err)
        return "失败."
    }

    log.Println("sha1Sum computed:", sha1SumB64,
        "sha1SumFromStore:", sha1SumFromStore)

    if sha1SumB64 == sha1SumFromStore {
        return "成功！"
    } else {
        return "失败."
    }
}

func trimStr(data string) (s string) {
    s = strings.Replace(data, "\n", "", -1)
    s = strings.Replace(s, "\t", "", -1)
    s = strings.Replace(s, " ", "", -1)
    return
}

func getSumFromStore(id string) (sum string, err error) {
    id = strings.TrimSpace(id)
    if id == "" {
        err = errors.New("error: dataId is empty.")
        return
    }
    f, err := os.Open(DataFile)
    if err != nil {
        return
    }
    defer f.Close()

    var dataLine string
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        line = strings.TrimSpace(line)
        if strings.HasPrefix(line, id) {
            dataLine = line
            break
        }
    }

    if err := scanner.Err(); err != nil {
        log.Println("scan store file error:", err, DataFile)
    }

    if dataLine == "" {
        err = errors.New("error: dataId not found in store: " + id)
        return
    } else {
        // parse line here.
        dataFields := strings.Split(dataLine, ",")
        if len(dataFields) < 2 {
            err = errors.New("record format error: " + dataLine)
            return
        } else {
            return dataFields[1], nil
        }
    }
}
