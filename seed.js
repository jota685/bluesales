require("dotenv").config();
const {Pool}=require("pg");
const bcrypt=require("bcryptjs");
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==="true"?{rejectUnauthorized:false}:undefined});
(async()=>{
 const c=await pool.connect();
 try{
  const fs=require("fs");
  await c.query(fs.readFileSync("schema.sql","utf8"));
  const count=(await c.query("SELECT COUNT(*) c FROM users")).rows[0].c;
  if(Number(count)===0){
   const password=process.env.ADMIN_INITIAL_PASSWORD||"Admin@123";
   const hash=await bcrypt.hash(password,12);
   const u=(await c.query("INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,'ADMIN') RETURNING id",["Administrador","admin@bluesales.local",hash])).rows[0].id;
   const p1=(await c.query("INSERT INTO products(name,category,price_cents) VALUES('Automação Pro','SaaS',249000) RETURNING id")).rows[0].id;
   const p2=(await c.query("INSERT INTO products(name,category,price_cents) VALUES('Consultoria Growth','Serviço',480000) RETURNING id")).rows[0].id;
   const p3=(await c.query("INSERT INTO products(name,category,price_cents) VALUES('Site Premium','Digital',319000) RETURNING id")).rows[0].id;
   const c1=(await c.query("INSERT INTO customers(name,email) VALUES('Marina Costa','marina@exemplo.com') RETURNING id")).rows[0].id;
   const c2=(await c.query("INSERT INTO customers(name,email) VALUES('Lucas Mendes','lucas@exemplo.com') RETURNING id")).rows[0].id;
   const c3=(await c.query("INSERT INTO customers(name,email) VALUES('Agência Norte','contato@agencianorte.com') RETURNING id")).rows[0].id;
   await c.query("INSERT INTO sales(customer_id,product_id,amount_cents,status,sold_at) VALUES($1,$2,249000,'PAID',NOW()),($3,$4,319000,'PENDING',NOW()-INTERVAL '1 day'),($5,$6,480000,'PAID',NOW()-INTERVAL '2 days')",[c1,p1,c2,p3,c3,p2]);
  }
  console.log("Banco inicializado.");
 }finally{c.release();await pool.end()}
})().catch(e=>{console.error(e);process.exit(1)});
