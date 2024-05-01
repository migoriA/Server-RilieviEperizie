import _http from "http";
import _https from "https";
import _url from "url";
import _fs from "fs";
import _express from "express";
import _dotenv from "dotenv";
import _cors from "cors";
import {Db, MongoClient, ObjectId} from "mongodb";
import _bcrypt from "bcryptjs";
import _jwt from "jsonwebtoken";
import _nodemailer from "nodemailer";
import {v2 as cloudinary} from 'cloudinary';

_dotenv.config({ "path": ".env" });


const DBNAME = process.env.DBNAME;
const connectionString: string = process.env.connectionStringAtlas;
const app = _express();


const HTTPS_PORT: number = parseInt(process.env.HTTPS_PORT);
let paginaErrore;
const PRIVATE_KEY = _fs.readFileSync("./keys/privateKey.pem", "utf8");
const CERTIFICATE = _fs.readFileSync("./keys/certificate.crt", "utf8");
const SIMMETRIC_KEY = process.env.SIMMETRIC_KEY
const CREDENTIALS = { "key": PRIVATE_KEY, "cert": CERTIFICATE };
const https_server = _http.createServer(app);

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.api_secret
})

https_server.listen(HTTPS_PORT, () => {
    init();
    console.log(`Il Server è in ascolto sulla porta ${HTTPS_PORT}`);
});

function init() {
    _fs.readFile("./static/error.html", function (err, data) {
        if (err) {
            paginaErrore = `<h1>Risorsa non trovata</h1>`;
        }
        else {
            paginaErrore = data.toString();
        }
    });
}



// 1. Request log
app.use("/", (req: any, res: any, next: any) => {
    console.log(`-----> ${req.method}: ${req.originalUrl}`);
    next();
});

// 2. Gestione delle risorse statiche
app.use("/", _express.static("./static"));

// 3. Lettura dei parametri POST di req["body"] (bodyParser)
app.use("/", _express.json({ "limit": "50mb" }));
app.use("/", _express.urlencoded({ "limit": "50mb", "extended": true }));

// 4. Log dei parametri GET, POST, PUT, PATCH, DELETE
app.use("/", (req: any, res: any, next: any) => {
    if (Object.keys(req["query"]).length > 0) {
        console.log(`       ${JSON.stringify(req["query"])}`);
    }
    if (Object.keys(req["body"]).length > 0) {
        console.log(`       ${JSON.stringify(req["body"])}`);
    }
    next();
});

// 5. Controllo degli accessi tramite CORS
const corsOptions = {
    origin: function (origin, callback) {
        return callback(null, true);
    },
    credentials: true
};
app.use("/", _cors(corsOptions));

const auth = {
    "user": process.env.EMAIL_USER,
    "pass": process.env.EMAIL_PASS
}
const trasporter = _nodemailer.createTransport({
    "service": "gmail",
    "auth": auth
})
let msg = _fs.readFileSync("./message.html", "utf8")

//********************************************************************************************//

app.post("/api/login",async (req, res, next) => {
    let user = req.body.username
    let pass = req.body.password
    let reg = new RegExp(`^${user}$`,"i")
    let filter = {"name":reg}

    if(user === 'Admin'){
        logIn(user,pass,res,req,filter)
    }
    else{
        res.status(401).send("Username non trovato")
    }
})

app.post("/api/userLogin",(req,res,next)=>{
    let user = req.body.username
    let pass = req.body.password
    let reg = new RegExp(`^${user}$`,"i")
    let filter = {"email":reg}

    if(user !== 'Admin'){
        logIn(user,pass,res,req,filter)
    }
    else{
        res.status(401).send("Username non trovato")
    }
})

async function logIn(user,pass,res,req,filter){
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("utenti")

    let rq = collection.findOne(filter,{"projection":{"name":1,"password":1}})
    rq.then((data)=>{
        if(!data){
            res.status(401).send("Username non trovato")
        }
        _bcrypt.compare(pass, data.password,(err,result)=>{
            if(err){
                res.status(500).send("bcrypt compare error" + err.message)
            }
            else{
                if(!result){
                    res.status(401).send("Password errata")
                }
                else{
                    let token = creaToken(data)
                    console.log(token)
                    res.setHeader("authorization",token)
                    //! Fa si che la header authorization venga restituita al client
                    res.setHeader("access-control-expose-headers","authorization")
                    res.send(user)
                }
            }
        })
    }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
}

function creaToken(user){
    let currentDate = Math.floor(new Date().getTime() / 1000)
    let payLoad = {
        "_id": user._id,
        "username": user.username,
        "iat": user.iat || currentDate,
        "exp": currentDate + parseInt(process.env.TOKEN_DURATION)
    }
    return _jwt.sign(payLoad, SIMMETRIC_KEY)
}
const GeneraCodice = () => {
    const alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numeri = "0123456789";
    const c = alfabeto + numeri;

    const Carattere = () => c.charAt(Math.floor(Math.random() * c.length))

    return new Array(6).fill('').reduce((acc) => acc + Carattere(), "");
}

app.post("/api/modifyPassword", async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    let user = req.body
    await client.connect()
    let password = GeneraCodice()
    user.password = _bcrypt.hashSync(password,10)
    const collection = client.db(DBNAME).collection("utenti")
    let rq = collection.updateOne({email: user.username}, {$set:{password:user.password}})
    rq.then((data)=>{
        msg = msg.replace("__user", user.username).replace("__password", password)
        console.log(auth)
        console.log(password)
        let mailOptions = {
            "from": auth.user,
            "to": user.username,
            "subject": "Rigenera password avvenuta",
            "html": msg
        }
        trasporter.sendMail(mailOptions, (err, info) => {
            console.log(info);
            console.log(err)
            if(!err) res.send(data)
        });
    }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
})

app.use("/api/", (req,res,next) => {
    if(!req.headers["authorization"]){
        res.status(403).send("Token mancante")
        //console.log("Dio cane")
    }
    else{
        let token = req.headers["authorization"]
        _jwt.verify(token, SIMMETRIC_KEY,(err,payload)=>{
            if(err){
                res.status(403).send("Token corrotto " + err)
                console.error("Dio cane")
            }
            else{
                let token = creaToken(payload)
                console.log(token)
                res.setHeader("authorization",token)
                //! Fa si che la header authorization venga restituita al client
                res.setHeader("access-control-expose-headers","authorization")
                req["payload"] = payload
                next()
            }
        })
    }
})

const StringaInData = (data: string) => {
    const [dataStr, ora] = data.split("T")
    //console.log(dataStr,ora)
    const [anno, mese, giorno] = dataStr.split("-").map(c => +c)
    //console.log(anno,mese,giorno)
    const [ore, minuti] = ora.split(":").map(c => +c)
    return new Date(anno, mese - 1, giorno, ore, minuti)
}
app.get("/api/homePageData",async (req,res,next)=>{
    console.log("Ciao")
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("perizie")
    let rq = collection.find().toArray()
    rq.then((data)=>{
        data = data.sort((a,b)=>{
            return StringaInData(b.time).getTime() - StringaInData(a.time).getTime()
        }).slice(0,3)
        //console.log(data)
        //console.log(data.map((a)=> a.codOp))
        let rq2 = client.db(DBNAME).collection("utenti").find().toArray().then((data2)=>{
            //console.log(data2.filter((a)=> data.map((b)=> b.codOp).includes(a._id)))
            data2 = data2.filter((a)=> data.map((b)=> +b.codOp).includes(a._id as any))
            //console.log(data2)
            res.send({"perizie":data,"utenti":data2})
        }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
    }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)})
})

app.get("/api/:collection/getPerizie", async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection(req.params.collection)
    let rq = collection.find().toArray()
    rq.then((data)=>{
        let join = client.db(DBNAME).collection("utenti")
        let rq = join.find().toArray().then((data2)=>{ res.send({"perizie":data,"utenti":data2})}).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
    }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)})
})

app.get("/api/:collection", async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection(req.params.collection)
    let rq = collection.find().toArray()
    rq.then((data)=>{res.send(data)}).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
})


app.post('/api/markers',async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection('perizie')
    let rq = collection.find().project({_id:1,coor:1}).toArray()
    rq.then((data)=>{
        //console.log(data)
        res.send(data)
    }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
})

app.post('/api/perizie/:id',async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection('perizie')
    let rq = collection.findOne({"_id":new ObjectId(req.params.id)})
    rq.then((data)=>{
        console.log(data)
        res.send(data)
    }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
})
app.patch('/api/updatePerizia/:id',async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection('perizie')
    delete req.body._id
    let rq = collection.replaceOne({"_id":new ObjectId(req.params.id)},req.body)
    rq.then((data)=>{
        console.log(data)
        res.send(data)
    }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
})



app.post("/api/addUser", async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    let user = req.body
    await client.connect()
    let password = GeneraCodice()
    user.password = _bcrypt.hashSync(password,10)
    const collection = client.db(DBNAME).collection("utenti")
    let rq = collection.insertOne(user)
    rq.then((data)=>{
        msg = msg.replace("__user", user.email).replace("__password", password)
        console.log(auth)
        let mailOptions = {
            "from": auth.user,
            "to": user.email,
            "subject": "Registrazione avvenuta con successo",
            "html": msg
        }
        trasporter.sendMail(mailOptions, (err, info) => {
            console.log(info);
            console.log(err)
            if(!err) res.send(data)
        });
    }).catch((err)=>{res.status(500).send("Errore esecuzione query "+ err.message)}).finally(() => client.close())
})



app.post("/api/destination/:id",async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection('perizie')
    let rq = collection.findOne({_id : new ObjectId(req.params.id)})
    rq.then((result)=>{
        console.log(result.coor)
        res.send(result)
    }).catch((err)=>{res.status(500).send('Errore esecuzione query ' + err.message)}).finally(()=>client.close())
})

app.post("/api/userHomeMobile", async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection('utenti')
    //console.log(req.body.user)
    let rq = collection.find({'email':req.body.user}).project({'_id':1}).toArray()
    rq.then((data)=>{
        //console.log(data)
        const collection2 = client.db(DBNAME).collection('perizie')
        //console.log(data[0]._id)
        let rq2 = collection2.find({'codOp':(data[0]._id).toString()}).toArray()
        rq2.then(data2 =>{
            res.send({'codOp': data[0]._id,'perizie':data2})
        }).catch(err => res.status(500).send("Errore esecuzione query "+ err.message)).finally(() => client.close())
    }).catch(err => res.status(500).send("Errore esecuzione query "+ err.message))

})

app.post("/api/addPerizia",async (req,res,next)=>{
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection('perizie')
    let perizia = req.body.perizia
    let map = perizia.img.map((i)=>{
        return new Promise((resolve,reject)=>{
            cloudinary.uploader.upload(i.url, { "folder": "RilieviEPerizie" })
            .catch((err) => {
                resolve(undefined)
            })
            .then(async function (response: any) {
                resolve(response.secure_url)
            });
        })
    })
    map = await Promise.all(map)
    if(map.some(m=>!m)){
        res.status(500).send(`Error while uploading file on Cloudinary:`);
        return
    }
    perizia.img.forEach((p,indice)=>{
        perizia.img[indice].url = map[indice]
    })
    let rq = collection.insertOne(perizia)
    rq.then(result=>{
        res.send("Ok")
    }).catch(err => res.status(500).send("errore")).finally(()=>client.close())
})
//********************************************************************************************//
// Default route e gestione degli errori
//********************************************************************************************//

app.use("/", (req, res, next) => {
    res.status(404);
    if (req.originalUrl.startsWith("/api/")) {
        res.send(`Api non disponibile`);
    }
    else {
        res.send(paginaErrore);
    }
});

app.use("/", (err, req, res, next) => {
    console.log("************* SERVER ERROR ***************\n", err.stack);
    res.status(500).send(err.message);
});