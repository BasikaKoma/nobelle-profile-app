const express = require('express');
const app = express();

app.get('/health', (req, res) => res.send('ok'));
app.get('/', (req, res) => res.send('Nobelle Profile App running'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Server running on port', port));
