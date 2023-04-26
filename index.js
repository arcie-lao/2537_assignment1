const express = require('express');

const session = require('express-session');

const app = express();

const port = process.env.PORT || 3020;

const node_session_secret = '3d2401ad-5f3f-4b35-a2cf-320f14abc524';


app.use(session({
    secret: node_session_secret,
    saveUninitialized: false,
    resave: true
}));

app.get('/', (req,res) => {
    if (req.session.numPageHits == null){
        req.session.numPageHits = 0;
    } else {
        req.session.numPageHits++;
    }

    const result = 'hello ' + req.session.numPageHits;

    res.send(result);
});

app.listen(port, () => {
    console.log("Listening on port " + port);
});