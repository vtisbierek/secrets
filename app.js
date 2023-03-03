require("dotenv").config(); //módulo que inclui meu arquivo .env de variáveis locais, para guardar minha chave de criptografia, o segredo da minha sessão, etc
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption"); //módulo que faz criptografia nas DBs do mongo usando chave de criptografia
//const md5 = require("md5"); //módulo que faz hashing usando o método MD5, que é um dos mais simples e rápidos (quando se trata de hashing, mais rápido = pior)
//const bcrypt = require("bcrypt"); //módulo que faz hashing e salting usando o método bcrypt, que é super lento (bom contra hackers)
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); //para usar esse cara, tem que instalar o módulo passport-local também, mas não precisa chamar ele no código, pois ele só é necessário como uma dependência do módulo passport-local-mongoose, e não diretamente
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const saltRounds = 10; //número de rodadas de adição de Salt + Hashing que serão aplicadas às minhas senhas

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session( //inicialização da sessão
    {
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false
    }
));

app.use(passport.initialize()); //inicialização do passaporte
app.use(passport.session()); //linha de código que diz para o nosso app usar o passaporte para lidar com a sessão que abrimos antes

mongoose.set('strictQuery', false);

mongoose.connect(process.env.MONGODB_URL, {useNewUrlParser: true}, () => {
    console.log("Connected to Daily Secrets DB");
});
/* mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true}, () => {
    console.log("Connected to UserDB");
}); */

const secretSchema = new mongoose.Schema(
    {
        content: String,
        author: {type: mongoose.Schema.Types.ObjectId, ref: "User"}
    }
)

const Secret = new mongoose.model("Secret", secretSchema);

const userSchema = new mongoose.Schema(
    {
        email: String, //esse campo não é mais utilizado depois que começamos a utilizar o passport
        password: String,
        googleId: String,
        githubId: String,
        secrets: [{type: mongoose.Schema.Types.ObjectId, ref: "Secret"}]   
    }
);

userSchema.plugin(passportLocalMongoose); //adicionando um plugin ao meu Schema, adicionando o passport-local-mongoose
userSchema.plugin(findOrCreate);

//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]}); //essa linha de código adiciona um plugin que implementa criptografia ao campo password

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy()); //Creates a configured passport-local LocalStrategy instance that can be used in passport.

//esses métodos são nativos do módulo passport, e funcionam com qualquer tipo de estratégia, tanto local quanto do google e todas as demais
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
});
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

//esses dois métodos são específicos do passport-local-mongoose, e só funcionam para estratégias locais
//passport.serializeUser(User.serializeUser()); //serialize só é necessário quando se utiliza sessões, é aqui que o passaporte faz o cookie com os dados do usuário
//passport.deserializeUser(User.deserializeUser()); //deserialize só é necessário quando se utiliza sessões, é aqui que o passaporte quebra o cookie para ver os dados do usuário

passport.use(new GoogleStrategy(
    {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({googleId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));

passport.use(new GitHubStrategy(
    {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/github/secrets"
    },
    function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ githubId: profile.id }, function (err, user) {
            return done(err, user);
        });
    }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", {scope: ["profile"]}));

app.get("/auth/google/secrets", 
    passport.authenticate("google", {failureRedirect: "/login"}),
    function(req, res) {
        res.redirect("/secrets");
});

app.get("/auth/github",
  passport.authenticate("github", {scope: ["user:email"]}));

app.get("/auth/github/secrets", 
    passport.authenticate("github", {failureRedirect: "/login"}),
    function(req, res) {
        res.redirect("/secrets");
});

app.get("/secrets", function(req, res){ //esse caminho só deve ser definido se estivermos utilizando sessões e autenticação de usuário (passport e/ou OAuth)
    if(req.isAuthenticated()){
        Secret.find(function(err, foundSecrets){
            if(err){
                res.send(err);
            } else{
                res.render("secrets", {secrets: foundSecrets});
            }
        });
    } else{
        res.redirect("/login");
    }
});

app.route("/submit")
    .get(function(req, res){
        if(req.isAuthenticated()){
            res.render("submit");
        } else{
            res.redirect("/login");
        }    
    })
    .post(function(req, res){
        const secret = new Secret(
            {
                content: req.body.secret,
                author: req.user.id
            }
        );
        secret.save(function(err, newSecret){
            if(err){
                res.send(err);
            } else{
                User.findById(req.user.id, function(err, foundUser){
                    foundUser.secrets.push(newSecret.id);
                    foundUser.save(function(err){
                        res.redirect("/secrets");
                    });
                });
            }
        });
    });

app.get("/logout", function(req, res){
    req.logout(function(err) {
        if (err){
            res.send(err);
        } else{
            res.redirect("/");
        }
    });
});

app.route("/register")
    .get(function(req, res){
        res.render("register");
    })
    .post(function(req, res){
        User.register({username: req.body.username}, req.body.password, function(err, user){ //modo utilizando sessões e autenticação de usuário (o passport-local-mongoose faz hashing e salting da senha automaticamente)
            if(err){
                res.send(err);
            } else{
                passport.authenticate("local")(req, res, function(){ //a função authenticate autentica o usuário com os dados que estão no user retornado por User.register
                    res.redirect("/secrets"); //como agora a gnt tá autenticando o usuário que está com uma sessão local aberta, enquanto ele estiver logado, ele pode ir direto pra página de segredos sem precisar passar pelas páginas de login e registro, então a gnt vai deixar ele usar o caminho /secrets, ao invés de só dar um render na página de segredos a partir do caminho /login ou /register
                });
            }
        });

        /* bcrypt.hash(req.body.password, saltRounds, function(err, hash) { //modo normal de fazer registro, sem utilização de sessões e cookies
            const newUser = new User(
                {
                    email: req.body.username,
                    //password: md5(req.body.password) //utilizando hashing MD5
                    //password: req.body.password //utilizando criptografia, eu passo o objeto com a senha em plain text, e quando dou o comando de newUser.save() o módulo de criptografia pega a minha chave de criptografia que tá no meu arquivo .env e encriptografa a senha, e aí na minha DB fica salva a senha encriptografada
                    password: hash
                }
            );
            newUser.save(function(err){
                if(err){
                    res.send(err);
                } else{
                    res.render("secrets");
                }
            });     
        })  */    
    });


app.route("/login")
    .get(function(req, res){
        res.render("login");
    })
    .post(function(req, res){
        const user = new User(
            {
                username: req.body.username, //quando construí o Schema do usuário (userSchema) eu não criei o campo username, mas esse campo é criado automaticamente quando instalei o plugin do passport-local-mongoose no meu Schema
                password: req.body.password
            }
        );

        req.login(user, function(err){
            if(err){
                res.send(err);
            } else{
                passport.authenticate("local", {failureRedirect: "/login"})(req, res, function(){ //a função authenticate autentica o usuário com os dados passados no user
                    res.redirect("/secrets");
                });
            }
        });

        /* User.findOne({email: req.body.username}, function(err, foundUser){ //modo normal de fazer login, sem utilização de sessões e cookies
            if(err){
                res.send(err);
            } else{
                if(foundUser){
                    bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
                        if(result){
                            res.render("secrets");    
                        } else{
                            res.render("login");
                        }
                    });
                    //if(foundUser.password === md5(req.body.password)){ //tem que fazer o hash da senha digitada para comparar com a salva
                    //    res.render("secrets");
                    //} else{
                    //    res.render("login");
                    //} 
                } else{
                    res.render("login");   
                }
            }
        }); */       
    });

app.listen(3000, function(){
    console.log("Server running on port 3000.");
});