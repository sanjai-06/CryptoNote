// server/server.js
const express = require('express');
const app = express();
const PORT = process.env.PORT || 5000;

app.get('/', (req, res) => {
  res.send('Cryptonote backend is running');
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
