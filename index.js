require("./utils.js");

const express = require('express');

const session = require('express-session');

const MongoStore = require('connect-mongo');

require('dotenv').config();

const bcrypt = require('bcrypt');

const Joi = require("joi");

const app = express();

const port = process.env.PORT || 3020;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const saltRounds = 12;

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    if(!req.session.authenticated){
        var html = "<button type=\'button\' onclick=\"location.href='/signup';\">Sign up</button>";
        html += "<br><button type='button' onclick=\"location.href='/login';\">Login<\/button>";

        res.send(html);
    } else {
        var html = `
            Hello, ${req.session.name}!<br>
            <button type=\'button\' onclick=\"location.href='/members';\">Go to Members Area</button><br>
            <form action=\'/logout\' method=\'DELETE\'><button>Sign out</button></form>        
        `;

        res.send(html);
    }
});

app.get('/nosql-injection', async (req,res) => {
	var name = req.query.name;

	if (!name) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+name);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(name);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({name: name}).project({name: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${name}</h1>`);
});

app.get('/signup', (req,res) => {
    var html = `
        create user
        <form action='/submitUser' method='post'>
            <input name='name' type='text' placeholder='name'><br>  
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `;

    res.send(html);
});

app.post('/submitUser', async(req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
		{
			name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});

	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       var html = `
        ${validationResult.error.details[0].message}<br>
        <a href=\"/signup\">Try again</a>
       `;
	   res.send(html);
	   return;
   }

   var hashedPassword = await bcrypt.hash(password, saltRounds);

   await userCollection.insertOne({name: name, email: email, password: hashedPassword});
   console.log("inserted user");


   req.session.authenticated = true;
   req.session.name = req.body.name;
   res.redirect("/members");

});

app.get('/login', (req,res) => {
    var html = `
        log in
        <form action='/loggingIn' method='post'>
            <input name='email' type='email' placeholder='email'></input><br>
            <input name='password' type='password' placeholder='password'></input><br>
            <button>Submit</button>
        </form>
    `;

    res.send(html);
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, _id: 1, name: 1}).toArray();

	if (result.length != 1) { //if user doesnt exist
		var html = `
            Invalid email/password combination

            <a href=\"/login\">Try again</a>
        `;
		res.send(html);
		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
        var html = `
            Invalid email/password combination

            <a href=\"/login\">Try again</a>
        `;
        res.send(html);
        return;
	}
});

app.get('/members', (req,res) => {
    if(!req.session.authenticated) {
        res.redirect("/");
    } else {
        var num = Math.floor(Math.random() * 3) + 1;
        var html = `<h1>Hello, ` + req.session.name + `</h1>`;
        html += '<img src=\'/cat/' + num + '\' style=\'width:250px\'>';
        html += '<br><form action=\'/logout\' method=\'DELETE\'><button>Sign out</button></form>';

        res.send(html);
    }
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect("/");
});

app.get('/cat/:id', (req,res) => {
    var cat = req.params.id;

    if(cat == 1){
        res.redirect("/hop.gif");
    } else if (cat == 2){
        res.redirect("/mad.gif");
    } else if(cat == 3){
        res.redirect("/team.gif");
    }
});

app.use(express.static(__dirname + "/public"));


app.get("*", (req,res) => {
    res.status(404);
    res.send("<img src='/404.jpg' style='width:250px;'><br>Page not found: Error 404");
});

app.listen(port, () => {
    console.log("Listening on port " + port);
});