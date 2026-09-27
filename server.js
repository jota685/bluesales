require("dotenv").config();
const express=require("express");
const path=require("path");
const fs=require("fs");
const bcrypt=require("bcryptjs");
const {Pool}=require("pg");
const session=require("express-session");
const PgSession=require("connect-pg-simple")(session);
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const nodemailer=require("nodemailer");
const {z}=require("zod");

const app=express();
const PORT=Number(process.env.PORT||3000);
const isProd=process.env.NODE_ENV==="production";
if(isProd && !process.env.SESSION_SECRET) throw new Error("SESSION_SECRET é obrigatório em produção.");
if(!process.env.DATABASE_URL) throw new Error("DATABASE_URL é obrigatório.");

const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==="true"?{rejectUnauthorized:false}:undefined});

app.set("trust proxy",1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"200kb"}));
app.use(express.urlencoded({extended:false}));
app.use(session({
 store:new PgSession({pool,tableName:"user_sessions",createTableIfMissing:true}),
 secret:process.env.SESSION_SECRET,
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:isProd,maxAge:1000*60*60*8}
}));

const loginLimiter=rateLimit({windowMs:15*60*1000,max:10,standardHeaders:true,legacyHeaders:false,message:{message:"Muitas tentativas. Aguarde alguns minutos."}});
const apiLimiter=rateLimit({windowMs:60*1000,max:180,standardHeaders:true,legacyHeaders:false});

async function q(text,params=[]){return pool.query(text,params)}
async function tx(fn){const c=await pool.connect();try{await c.query("BEGIN");const r=await fn(c);await c.query("COMMIT");return r}catch(e){await c.query("ROLLBACK");throw e}finally{c.release()}}
const money=n=>new Intl.NumberFormat("pt-BR",{style:"currency",currency:"BRL"}).format(Number(n||0)/100);

async function auth(req,res,next){
 if(!req.session.userId)return res.status(401).json({error:"UNAUTHENTICATED",message:"Faça login para continuar."});
 const {rows}=await q("SELECT id,name,email,role,avatar_url FROM users WHERE id=$1 AND active=true",[req.session.userId]);
 if(!rows[0])return req.session.destroy(()=>res.status(401).json({error:"UNAUTHENTICATED",message:"Sessão inválida."}));
 req.user=rows[0];next();
}
const role=(...roles)=>(req,res,next)=>roles.includes(req.user?.role)?next():res.status(403).json({error:"FORBIDDEN",message:"Acesso restrito. Esta função está disponível apenas para o administrador."});
const idSchema=z.coerce.number().int().positive();

const userSchema=z.object({name:z.string().trim().min(2).max(100),email:z.string().email().max(254),role:z.enum(["ADMIN","USER"]).default("USER"),password:z.string().min(8).max(128)});
const productSchema=z.object({name:z.string().trim().min(2).max(150),category:z.string().trim().max(80).optional().default("Digital"),priceCents:z.coerce.number().int().nonnegative(),active:z.boolean().optional().default(true)});
const customerSchema=z.object({name:z.string().trim().min(2).max(150),email:z.string().email().max(254).optional().or(z.literal("")),active:z.boolean().optional().default(true)});
const saleSchema=z.object({customerId:z.coerce.number().int().positive().nullable().optional(),productId:z.coerce.number().int().positive().nullable().optional(),amountCents:z.coerce.number().int().nonnegative(),status:z.enum(["PAID","PENDING","CANCELLED"])}); 

app.post("/api/login",loginLimiter,async(req,res)=>{
 try{
  const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
  if(!email||!password)return res.status(400).json({message:"Informe e-mail e senha."});
  const {rows}=await q("SELECT * FROM users WHERE lower(email)=lower($1) AND active=true",[email]);
  const u=rows[0];
  if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({message:"E-mail ou senha inválidos."});
  req.session.regenerate(err=>{
   if(err)return res.status(500).json({message:"Falha ao criar sessão."});
   req.session.userId=u.id;
   req.session.save(err2=>err2?res.status(500).json({message:"Falha ao salvar sessão."}):res.json({user:{id:u.id,name:u.name,email:u.email,role:u.role,avatar_url:u.avatar_url}}));
  });
 }catch(e){res.status(500).json({message:"Erro interno."})}
});
app.post("/api/logout",auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",auth,(req,res)=>res.json({user:req.user}));

app.get("/api/dashboard",apiLimiter,auth,async(req,res)=>{
 const [rev,sales,mrr,customers,orders,products]=await Promise.all([
  q("SELECT COALESCE(SUM(amount_cents),0)::bigint revenue FROM sales WHERE status='PAID'"),
  q("SELECT COUNT(*)::int sales FROM sales WHERE status='PAID'"),
  q("SELECT COALESCE(SUM(amount_cents),0)::bigint mrr FROM sales WHERE status='PAID' AND sold_at>=NOW()-INTERVAL '30 days'"),
  q("SELECT COUNT(*)::int c FROM customers WHERE active=true"),
  q("SELECT COUNT(*)::int c FROM sales"),
  q("SELECT COUNT(*)::int c FROM products WHERE active=true")
 ]);
 const revenue=Number(rev.rows[0].revenue),count=sales.rows[0].sales;
 res.json({metrics:{revenue:money(revenue),mrr:money(Number(mrr.rows[0].mrr)),avgTicket:money(count?Math.round(revenue/count):0),sales:count},secondary:{customers:customers.rows[0].c,orders:orders.rows[0].c,products:products.rows[0].c}});
});

app.get("/api/products",auth,async(req,res)=>res.json((await q("SELECT id,name,category,price_cents AS \"priceCents\",active,created_at AS \"createdAt\" FROM products ORDER BY id DESC")).rows));
app.post("/api/products",auth,async(req,res)=>{const v=productSchema.parse(req.body);const r=await q("INSERT INTO products(name,category,price_cents,active) VALUES($1,$2,$3,$4) RETURNING id,name,category,price_cents AS \"priceCents\",active", [v.name,v.category,v.priceCents,v.active]);res.status(201).json(r.rows[0])});
app.patch("/api/products/:id",auth,async(req,res)=>{const id=idSchema.parse(req.params.id),v=productSchema.partial().parse(req.body);const r=await q("UPDATE products SET name=COALESCE($1,name),category=COALESCE($2,category),price_cents=COALESCE($3,price_cents),active=COALESCE($4,active) WHERE id=$5 RETURNING id,name,category,price_cents AS \"priceCents\",active",[v.name??null,v.category??null,v.priceCents??null,v.active??null,id]);if(!r.rows[0])return res.status(404).json({message:"Produto não encontrado."});res.json(r.rows[0])});
app.delete("/api/products/:id",auth,async(req,res)=>{const id=idSchema.parse(req.params.id);const r=await q("UPDATE products SET active=false WHERE id=$1 RETURNING id",[id]);if(!r.rows[0])return res.status(404).json({message:"Produto não encontrado."});res.json({ok:true})});

app.get("/api/customers",auth,async(req,res)=>res.json((await q("SELECT id,name,email,active,created_at AS \"createdAt\" FROM customers ORDER BY id DESC")).rows));
app.post("/api/customers",auth,async(req,res)=>{const v=customerSchema.parse(req.body);const r=await q("INSERT INTO customers(name,email,active) VALUES($1,$2,$3) RETURNING id,name,email,active",[v.name,v.email||null,v.active]);res.status(201).json(r.rows[0])});
app.patch("/api/customers/:id",auth,async(req,res)=>{const id=idSchema.parse(req.params.id),v=customerSchema.partial().parse(req.body);const r=await q("UPDATE customers SET name=COALESCE($1,name),email=COALESCE($2,email),active=COALESCE($3,active) WHERE id=$4 RETURNING id,name,email,active",[v.name??null,v.email??null,v.active??null,id]);if(!r.rows[0])return res.status(404).json({message:"Cliente não encontrado."});res.json(r.rows[0])});
app.delete("/api/customers/:id",auth,async(req,res)=>{const id=idSchema.parse(req.params.id);await q("UPDATE customers SET active=false WHERE id=$1",[id]);res.json({ok:true})});

app.get("/api/sales",auth,async(req,res)=>res.json((await q(`SELECT s.id,s.customer_id AS "customerId",c.name customer,s.product_id AS "productId",p.name product,s.amount_cents AS "amountCents",s.status,s.sold_at AS "soldAt" FROM sales s LEFT JOIN customers c ON c.id=s.customer_id LEFT JOIN products p ON p.id=s.product_id ORDER BY s.sold_at DESC`)).rows));
app.post("/api/sales",auth,async(req,res)=>{const v=saleSchema.parse(req.body);const r=await q("INSERT INTO sales(customer_id,product_id,amount_cents,status) VALUES($1,$2,$3,$4) RETURNING id",[v.customerId??null,v.productId??null,v.amountCents,v.status]);res.status(201).json(r.rows[0])});

app.get("/api/admin/users",auth,role("ADMIN"),async(req,res)=>res.json((await q("SELECT id,name,email,role,active,created_at AS \"createdAt\" FROM users ORDER BY id DESC")).rows));
app.post("/api/admin/users",auth,role("ADMIN"),async(req,res)=>{
 const v=userSchema.parse(req.body),hash=await bcrypt.hash(v.password,12);
 try{const r=await q("INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,name,email,role,active",[v.name,v.email.toLowerCase(),hash,v.role]);res.status(201).json(r.rows[0])}
 catch(e){if(e.code==="23505")return res.status(409).json({message:"E-mail já cadastrado."});throw e}
});
app.patch("/api/admin/users/:id",auth,role("ADMIN"),async(req,res)=>{
 const id=idSchema.parse(req.params.id),v=userSchema.partial().omit({password:true}).parse(req.body);
 if(id===req.user.id && v.role==="USER")return res.status(400).json({message:"O administrador atual não pode remover a própria permissão."});
 const r=await q("UPDATE users SET name=COALESCE($1,name),email=COALESCE($2,email),role=COALESCE($3,role) WHERE id=$4 RETURNING id,name,email,role,active",[v.name??null,v.email?.toLowerCase()??null,v.role??null,id]);
 if(!r.rows[0])return res.status(404).json({message:"Usuário não encontrado."});res.json(r.rows[0]);
});
app.patch("/api/admin/users/:id/password",auth,role("ADMIN"),async(req,res)=>{const id=idSchema.parse(req.params.id),password=z.string().min(8).max(128).parse(req.body.password);await q("UPDATE users SET password_hash=$1 WHERE id=$2",[await bcrypt.hash(password,12),id]);res.json({ok:true})});
app.patch("/api/admin/users/:id/status",auth,role("ADMIN"),async(req,res)=>{const id=idSchema.parse(req.params.id);if(id===req.user.id)return res.status(400).json({message:"Não desative a própria conta."});await q("UPDATE users SET active=$1 WHERE id=$2",[!!req.body.active,id]);res.json({ok:true})});
app.put("/api/admin/profile",auth,role("ADMIN"),async(req,res)=>{const v=z.object({name:z.string().trim().min(2).max(100),email:z.string().email()}).parse(req.body);const r=await q("UPDATE users SET name=$1,email=$2 WHERE id=$3 RETURNING id,name,email,role,avatar_url",[v.name,v.email.toLowerCase(),req.user.id]);res.json({user:r.rows[0]})});
app.put("/api/admin/password",auth,role("ADMIN"),async(req,res)=>{const v=z.object({currentPassword:z.string(),newPassword:z.string().min(8).max(128)}).parse(req.body);const {rows}=await q("SELECT password_hash FROM users WHERE id=$1",[req.user.id]);if(!(await bcrypt.compare(v.currentPassword,rows[0].password_hash)))return res.status(400).json({message:"Senha atual incorreta."});await q("UPDATE users SET password_hash=$1 WHERE id=$2",[await bcrypt.hash(v.newPassword,12),req.user.id]);res.json({ok:true})});

const resetSchema=z.object({email:z.string().email()});
app.post("/api/forgot-password",loginLimiter,async(req,res)=>{
 const {email}=resetSchema.parse(req.body);
 const {rows}=await q("SELECT id,email FROM users WHERE lower(email)=lower($1) AND active=true",[email]);
 // Resposta genérica evita enumeração de contas.
 if(rows[0]){
   const raw=require("crypto").randomBytes(32).toString("hex");
   const hash=require("crypto").createHash("sha256").update(raw).digest("hex");
   await q("DELETE FROM password_resets WHERE user_id=$1",[rows[0].id]);
   await q("INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 minutes')",[rows[0].id,hash]);
   if(process.env.SMTP_HOST){
    const transporter=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:process.env.SMTP_SECURE==="true",auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
    const url=`${process.env.APP_URL}/reset-password?token=${raw}`;
    await transporter.sendMail({from:process.env.SMTP_FROM,to:rows[0].email,subject:"Redefinição de senha — BlueSales",text:`Redefina sua senha: ${url}\nO link expira em 30 minutos.`});
   } else console.log("RESET LINK (configure SMTP):",`${process.env.APP_URL||"http://localhost:3000"}/reset-password?token=${raw}`);
 }
 res.json({message:"Se o e-mail estiver cadastrado, enviaremos instruções para redefinir a senha."});
});
app.post("/api/reset-password",async(req,res)=>{
 const token=z.string().min(20).parse(req.body.token),password=z.string().min(8).max(128).parse(req.body.password);
 const hash=require("crypto").createHash("sha256").update(token).digest("hex");
 const {rows}=await q("SELECT user_id FROM password_resets WHERE token_hash=$1 AND expires_at>NOW()",[hash]);
 if(!rows[0])return res.status(400).json({message:"Token inválido ou expirado."});
 await tx(async c=>{await c.query("UPDATE users SET password_hash=$1 WHERE id=$2",[await bcrypt.hash(password,12),rows[0].user_id]);await c.query("DELETE FROM password_resets WHERE user_id=$1",[rows[0].user_id]);});
 res.json({ok:true});
});

app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.use((err,req,res,next)=>{
 console.error(err);
 if(err instanceof z.ZodError)return res.status(400).json({message:"Dados inválidos.",details:err.issues.map(x=>x.path.join(".")+": "+x.message)});
 res.status(500).json({message:"Erro interno do servidor."});
});
async function startServer() {
  try {await q(fs.readFileSync("schema.sql", "utf8"));
console.log("BANCO DE DADOS INICIALIZADO.");
    if (process.env.RESET_ADMIN_PASSWORD === "true") {
      const password = process.env.ADMIN_INITIAL_PASSWORD;

      if (!password) {
        throw new Error("ADMIN_INITIAL_PASSWORD não configurada.");
      }

      const hash = await bcrypt.hash(password, 12);

      const result = await q(
        `UPDATE users
         SET password_hash=$1, role='ADMIN', active=true
         WHERE lower(email)=lower($2)
         RETURNING id`,
        [hash, "admin@bluesales.local"]
      );

      if (result.rowCount === 0) {
        console.log("Administrador não encontrado.");
      } else {
        console.log("SENHA DO ADMINISTRADOR REDEFINIDA COM SUCESSO.");
      }
    }

    app.listen(PORT, () =>
      console.log(
        `BlueSales em ${process.env.APP_URL || `http://localhost:${PORT}`}`
      )
    );
  } catch (e) {
    console.error("Erro ao iniciar BlueSales:", e);
    process.exit(1);
  }
}

startServer();
