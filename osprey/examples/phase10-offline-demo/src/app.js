import { decodeUnsafe } from "demo-codec";

function decodeRequest(req) {
  return decodeUnsafe(req.body);
}

function uploadHandler(req, res) {
  return res.send(decodeRequest(req));
}

app.post("/decode", uploadHandler);
