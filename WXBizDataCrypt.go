package WXBizDataCrypt

import(
	"github.com/buger/jsonparser"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"log"
)



type  WXBizDataCrypt struct {
	appId string
	sessionKey string
}


// type WaterMark struct {
// 	TimeStamp string `json:"timestamp"`
// 	AppID string `json:"appid"`
// }


// type WXUserInfo struct {
// 	OpenID  string `json:"openId"`
// 	NickName  string `json:"nickName"`
// 	Gender int	`json:"gender"`
// 	Language string	`json:"language"`
// 	City string	`json:"city"`
// 	Province string	`json:"province"`
// 	Country string `json:"country"`
// 	AvatarUrl string `json:"avatarUrl"`
// 	UnionID string	`json:"unionId"`
// 	WaterMark WaterMark `json:"watermark"`
// }


func checkError(err  error, id string) {
	if err!= nil {
		log.Fatal("Wrong position is " + id, err)
	}
}


func (wx *WXBizDataCrypt) decrypt(encryptedData string, iv string)  string {
		// The sessionkey & encryptedData & iv are base64 encode
		// So we need to use base64 to decode it first
		sessionKey,err := base64.StdEncoding.DecodeString(wx.sessionKey)
		checkError(err, "1")
		encryptedDataByte,err := base64.StdEncoding.DecodeString(encryptedData)
		checkError(err, "2")
		ivByte,err := base64.StdEncoding.DecodeString(iv)
		checkError(err, "3")

		block,err := aes.NewCipher(sessionKey)
		checkError(err, "4")

		if len(encryptedDataByte) < aes.BlockSize {
			err = errors.New("Ciphertext block size is too short!")
			checkError(err, "5")
		}

		//The wechat biz data use mode CBC, which use block
	    mode := cipher.NewCBCDecrypter(block, ivByte)
	    mode.CryptBlocks(encryptedDataByte, encryptedDataByte)
		
		// var dat WXUserInfo
		// fmt.Println(string(encryptedDataByte))
		// json.Unmarshal(encryptedDataByte, &dat)
		// return dat
		openId,err := jsonparser.GetString(encryptedDataByte,"openId")
		checkError(err, "6")
		return openId
} 


// func main(){
// 	ha := WXBizDataCrypt{appId: "wx4f4bc4dec97d474b",
// 		sessionKey : "tiihtNczf5v6AKRyjwEUhQ=="}
// 	encryptedData := "CiyLU1Aw2KjvrjMdj8YKliAjtP4gsMZMQmRzooG2xrDcvSnxIMXFufNstNGTyaGS9uT5geRa0W4oTOb1WT7fJlAC+oNPdbB+3hVbJSRgv+4lGOETKUQz6OYStslQ142dNCuabNPGBzlooOmB231qMM85d2/fV6ChevvXvQP8Hkue1poOFtnEtpyxVLW1zAo6/1Xx1COxFvrc2d7UL/lmHInNlxuacJXwu0fjpXfz/YqYzBIBzD6WUfTIF9GRHpOn/Hz7saL8xz+W//FRAUid1OksQaQx4CMs8LOddcQhULW4ucetDf96JcR3g0gfRK4PC7E/r7Z6xNrXd2UIeorGj5Ef7b1pJAYB6Y5anaHqZ9J6nKEBvB4DnNLIVWSgARns/8wR2SiRS7MNACwTyrGvt9ts8p12PKFdlqYTopNHR1Vf7XjfhQlVsAJdNiKdYmYVoKlaRv85IfVunYzO0IKXsyl7JCUjCpoG20f0a04COwfneQAGGwd5oa+T8yO5hzuyDb/XcxxmK01EpqOyuxINew=="
// 	iv := "r7BXXKkLb8qrSNn05n0qiA=="

// 	res := ha.decrypt(encryptedData, iv)
// 	fmt.Println(res)
// }