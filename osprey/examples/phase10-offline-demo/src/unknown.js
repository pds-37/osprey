async function dynamicHandler(req, res) {
  const packageName = req.query.package;
  const codec = await import(packageName);
  return res.send(codec.decodeUnsafe(req.body));
}

app.post("/dynamic", dynamicHandler);
