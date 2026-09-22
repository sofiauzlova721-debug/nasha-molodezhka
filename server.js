const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_PATH || path.join(__dirname, "data.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 first_name TEXT NOT NULL,
 last_name TEXT NOT NULL,
 birth_date TEXT,
 verse TEXT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 points INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS prayers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 text TEXT NOT NULL,
 anonymous INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 event_date TEXT NOT NULL,
 description TEXT DEFAULT ''
);
`);

const defaults = {
 pool_points:"7450", pool_target:"10000", pool_goal:"Большая молодёжная тусовка",
 verse:"«Будьте друг ко другу добры, сострадательны, прощайте друг друга…» — Ефесянам 4:32",
 prayer:"За мир, мудрость и поддержку друг друга.",
 max_url:"https://max.ru/join/zNA6CC-OTmCLKYeOcioHticvCxDIFKUqzN7bcn2oVnc",
 telegram_url:"",
 level1_name:"Новичок", level1_min:"0",
 level2_name:"Ученик", level2_min:"1000",
 level3_name:"Служитель", level3_min:"2000",
 level4_name:"Лидер", level4_min:"3000"
};

const put = db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)");
for (const [k,v] of Object.entries(defaults)) put.run(k,v);

if (!db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get()) {
 const email = process.env.ADMIN_EMAIL || "admin@example.com";
 const pass = process.env.ADMIN_PASSWORD || "change-me-now";
 db.prepare(`INSERT INTO users(first_name,last_name,email,password_hash,role)
 VALUES(?,?,?,?,?)`).run("Администратор","Молодёжки",email,bcrypt.hashSync(pass,12),"admin");
 console.log(`Admin created: ${email}`);
}

app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(session({
 secret: process.env.SESSION_SECRET || "change-this-secret",
 resave:false,
 saveUninitialized:false,
 cookie:{
   httpOnly:true,
   sameSite:"lax",
   secure:process.env.NODE_ENV==="production",
   maxAge:1000*60*60*24*7
 }
}));

app.use(express.static(path.join(__dirname,"public")));

function settings(){
 const rows=db.prepare("SELECT key,value FROM settings").all();
 return Object.fromEntries(rows.map(r=>[r.key,r.value]));
}

function auth(req,res,next){
 if(!req.session.userId)
   return res.status(401).json({error:"Нужен вход"});
 next();
}

function admin(req,res,next){
 if(!req.session.userId)
   return res.status(401).json({error:"Нужен вход"});

 const u=db.prepare("SELECT role FROM users WHERE id=?").get(req.session.userId);

 if(!u || u.role!=="admin")
   return res.status(403).json({error:"Только администратор"});

 next();
}

function safeUser(u){
 return {
   id:u.id,
   first_name:u.first_name,
   last_name:u.last_name,
   birth_date:u.birth_date,
   verse:u.verse,
   email:u.email,
   role:u.role,
   points:u.points
 };
}

app.get("/api/config",(req,res)=>res.json(settings()));

app.get("/api/me",(req,res)=>{
 if(!req.session.userId)
   return res.json(null);

 const u=db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId);

 res.json(safeUser(u));
});

app.post("/api/register",async(req,res)=>{
 const {
   first_name,
   last_name,
   birth_date,
   verse,
   email,
   password
 }=req.body;

 if(!first_name||!last_name||!email||!password)
   return res.status(400).json({
     error:"Заполните имя, фамилию, email и пароль"
   });

 if(password.length<6)
   return res.status(400).json({
     error:"Пароль должен быть не короче 6 символов"
   });

 try{
   const hash=await bcrypt.hash(password,12);

   const info=db.prepare(`
     INSERT INTO users(
       first_name,
       last_name,
       birth_date,
       verse,
       email,
       password_hash
     )
     VALUES(?,?,?,?,?,?)
   `).run(
     first_name,
     last_name,
     birth_date||"",
     verse||"",
     email.toLowerCase(),
     hash
   );

   req.session.userId=info.lastInsertRowid;

   res.json({ok:true});
 }catch(e){
   res.status(400).json({
     error:"Такой email уже зарегистрирован"
   });
 }
});

app.post("/api/login",async(req,res)=>{
 const u=db.prepare(
   "SELECT * FROM users WHERE email=?"
 ).get((req.body.email||"").toLowerCase());

 if(
   !u ||
   !(await bcrypt.compare(
     req.body.password||"",
     u.password_hash
   ))
 ){
   return res.status(401).json({
     error:"Неверный email или пароль"
   });
 }

 req.session.userId=u.id;

 res.json({ok:true});
});

app.post("/api/logout",(req,res)=>{
 req.session.destroy(()=>res.json({ok:true}));
});

app.get("/api/dashboard",auth,(req,res)=>{
 const s=settings();

 const me=db.prepare(
   "SELECT * FROM users WHERE id=?"
 ).get(req.session.userId);

 const prayers=db.prepare(`
   SELECT text,anonymous,created_at
   FROM prayers
   ORDER BY id DESC
   LIMIT 30
 `).all();

 const events=db.prepare(`
   SELECT *
   FROM events
   ORDER BY event_date ASC
   LIMIT 30
 `).all();

 res.json({
   me:safeUser(me),
   settings:s,
   prayers,
   events
 });
});

app.post("/api/prayers",auth,(req,res)=>{
 if(!req.body.text?.trim())
   return res.status(400).json({
     error:"Напишите просьбу"
   });

 db.prepare(`
   INSERT INTO prayers(user_id,text,anonymous)
   VALUES(?,?,?)
 `).run(
   req.session.userId,
   req.body.text.trim(),
   req.body.anonymous?1:0
 );

 res.json({ok:true});
});

app.put("/api/profile",auth,(req,res)=>{
 const {
   first_name,
   last_name,
   birth_date,
   verse
 }=req.body;

 db.prepare(`
   UPDATE users
   SET first_name=?,
       last_name=?,
       birth_date=?,
       verse=?
   WHERE id=?
 `).run(
   first_name,
   last_name,
   birth_date||"",
   verse||"",
   req.session.userId
 );

 res.json({ok:true});
});

app.get("/api/admin/users",admin,(req,res)=>{
 const users=db.prepare(`
   SELECT
     id,
     first_name,
     last_name,
     birth_date,
     verse,
     email,
     role,
     points
   FROM users
   ORDER BY last_name,first_name
 `).all();

 res.json(users);
});

app.put("/api/admin/settings",admin,(req,res)=>{
 const allowed=Object.keys(defaults);

 const tx=db.transaction(body=>{
   for(const k of allowed){
     if(body[k]!==undefined){
       db.prepare(`
         INSERT INTO settings(key,value)
         VALUES(?,?)
         ON CONFLICT(key)
         DO UPDATE SET value=excluded.value
       `).run(k,String(body[k]));
     }
   }
 });

 tx(req.body);

 res.json({ok:true});
});

app.put("/api/admin/users/:id/points",admin,(req,res)=>{
 const delta=Number(req.body.delta||0);

 if(!Number.isFinite(delta))
   return res.status(400).json({
     error:"Некорректное число"
   });

 db.prepare(`
   UPDATE users
   SET points=MAX(0,points+?)
   WHERE id=?
 `).run(
   Math.trunc(delta),
   req.params.id
 );

 const u=db.prepare(`
   SELECT id,first_name,last_name,points
   FROM users
   WHERE id=?
 `).get(req.params.id);

 const s=settings();

 const next=Math.max(
   0,
   Number(s.pool_points||0)+Math.trunc(delta)
 );

 db.prepare(`
   INSERT INTO settings(key,value)
   VALUES('pool_points',?)
   ON CONFLICT(key)
   DO UPDATE SET value=excluded.value
 `).run(String(next));

 res.json(u);
});

app.post("/api/admin/events",admin,(req,res)=>{
 const {
   title,
   event_date,
   description
 }=req.body;

 if(!title||!event_date)
   return res.status(400).json({
     error:"Нужны название и дата"
   });

 const r=db.prepare(`
   INSERT INTO events(
     title,
     event_date,
     description
   )
   VALUES(?,?,?)
 `).run(
   title,
   event_date,
   description||""
 );

 res.json({
   id:r.lastInsertRowid
 });
});

app.delete("/api/admin/events/:id",admin,(req,res)=>{
 db.prepare(
   "DELETE FROM events WHERE id=?"
 ).run(req.params.id);

 res.json({ok:true});
});

app.listen(PORT,()=>{
 console.log(
   `Nasha Molodezhka: http://localhost:${PORT}`
 );
});
