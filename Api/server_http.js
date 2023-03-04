const http = require("http");
const host = '127.0.0.1';
const port = 8080;
const fs = require('fs').promises;



const requestListener = function (req, res) {

    fs.readFile("/media/alien/30C8-40D5/Proyects/Prl-shark/server/html_page.html")
    .then(contents => {
        res.setHeader("Content-Type", "application/json");
        res.writeHead(200);
        res.end(`{"message": "This is a JSON response"}`);
        res.setHeader("Content-Type", "text/html");
        res.writeHead(200);
        res.end(contents);
    })
    .catch(err => {
        res.writeHead(500);
        res.end(err);
        return;
    });
};



const server = http.createServer(requestListener);
server.listen(port, host, () => {
    console.log(`Server is running on http://${host}:${port}`);
});
