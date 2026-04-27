# JWT CTF 題目設計
前端設計請使用 @sample_templates 的設計模式
每一題都是打開介面後 會給一個 user 是 guest 的 jwt token
他們要 fake 成 whale 來拿 flag

底下則是會有程式碼框顯示出這次 JWT 處理器的 soure code 是什麼

這次的目錄結構請你以 python flask 完成
底下要有 app.py 接著對於 /level1~/level4 的路由他們的 jwt src 分別是 level1.py ~ level4.py, 其他 static 和 templates 你自己知道
請自行實作 jwt 庫


levels
1: 預設用 HS256 but none algorithm can be set
2: HS256 secret can be brute force (secret 設定成 1001) (注意到這題的前端在顯示的時候 secret 要顯示 REDACTED)
3: HS256 可以指定 key file 是什麼
4: HS256 和 RS256 同時接受，並且是從 pem file 讀取 secret 的 (這次檔名不可指定)，考他們 confusion attack


