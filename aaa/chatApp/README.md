chatApp
前端位于 client/，后端使用 server.js（同端口提供静态页面和 WebSocket）。

功能概览:
在线成员列表（Online list）
私聊（Direct message, dm）
群发（Broadcast / Send to all）
点对点文件传输(未实现)

终端启动：
npm ci
npm start

启动成功后访问：
网页：http://localhost:8080
WebSocket 地址默认就是 ws://localhost:8080（已在前端自动匹配同端口）