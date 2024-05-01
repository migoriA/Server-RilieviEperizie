import bcrypt from "bcryptjs" // + @types
import {MongoClient, ObjectId}  from "mongodb"
import dotenv from "dotenv"
dotenv.config({ path: ".env" })


const CONNECTION_STRING:string = process.env.connectionStringAtlas
const DBNAME = process.env.DBNAME


const client = new MongoClient(CONNECTION_STRING)
client.connect().then((result) => {
  let collection = client.db(DBNAME).collection("utenti")
  let rq = collection.find(  ).toArray()
  rq.then((result) => {
    //console.log(result)
    let promises:any[] = []
    let cnt = 0
    for(let item of result){
      let reg = new RegExp("^\\$2[aby]\\$10\\$.{53}$")
      if(!reg.test(item.password)){
        //let _id = new ObjectId(item._id)
        //console.log(_id)
        let newPassword = bcrypt.hashSync(item.password,10)
        item.password = newPassword
        delete item._id
        let promise = collection.replaceOne({'name':item.name},item)
        promises.push(promise)
        cnt++
      }
    }
    Promise.all(promises).then((result)=>{
      console.log("Password aggiornate correttamente: "+cnt)
    }).catch(()=>{
      console.log("GAY")
    }).finally(()=> client.close())
  }).catch((err) => {
    console.log(err) 
    client.close()
  })
}).catch((err) => console.log(err))


