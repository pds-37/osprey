import { decodeUnsafe } from "demo-codec";

function backgroundTask(payload) {
  return payload;
}

function healthHandler(req, res) {
  return res.send("ok");
}

app.get("/health", healthHandler);
