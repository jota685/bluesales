require("dotenv").config();

const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const fs = require("fs");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_SSL === "true"
      ? { rejectUnauthorized: false }
      : undefined
});

(async () => {
  const c = await pool.connect();

  try {
    await c.query(fs.readFileSync("schema.sql", "utf8"));

    const password =
      process.env.ADMIN_INITIAL_PASSWORD || "Admin@123";

    const hash = await bcrypt.hash(password, 12);

    // Cria o administrador se não existir.
    // Se já existir, redefine a senha e garante acesso ADMIN.
    await c.query(
      `
      INSERT INTO users
        (name, email, password_hash, role, active)
      VALUES
        ($1, $2, $3, 'ADMIN', true)

      ON CONFLICT (email)
      DO UPDATE SET
        password_hash = EXCLUDED.password_hash,
        role = 'ADMIN',
        active = true
      `,
      [
        "Administrador",
        "admin@bluesales.local",
        hash
      ]
    );

    console.log("Administrador configurado.");
    console.log("E-mail: admin@bluesales.local");

  } finally {
    c.release();
    await pool.end();
  }
})().catch(e => {
  console.error(e);
  process.exit(1);
});

