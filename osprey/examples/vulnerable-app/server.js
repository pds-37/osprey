const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', version: '1.0.0' });
});

app.post('/api/merge', (req, res) => {
  const merged = _.merge({}, req.body);
  res.json({ success: true, result: merged });
});

app.listen(8080, () => {
  console.log('Server running on port 8080');
});
