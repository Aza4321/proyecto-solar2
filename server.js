const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const nodemailer = require("nodemailer");
const helmet = require("helmet"); // 👈 AQUÍ  se agrego (HTTP Security Headers)

const app = express();
app.use(express.json());
app.use(cors());

// 🔒 AQUÍ VA HELMET, se definio  la política CSP manualmente
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: []
      }
    }
  })
);


// 🔥 CONFIGURACIÓN DEL CORREO
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "Jona00043@gmail.com",
    pass: "a z i x b d f f y m m h n e b m"
  }
});


mongoose.connect("mongodb://localhost:27017/cafeteria")
  .then(() => console.log("Conectado a MongoDB"))
  .catch(err => console.log(err));

// Modelo de usuario
const UsuarioSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  codigo_2fa: String,
  resetToken: String
});

const Usuario = mongoose.model("usuarios", UsuarioSchema);

// REGISTRO
app.post("/registro", async (req, res) => {
  const { email, password } = req.body;

    // 🔐 VALIDACIÓN DE CONTRASEÑA (AQUÍ)
  const regex = /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;


  if (!regex.test(password)) {
    return res.json({
      mensaje: "Contraseña insegura. Usa mínimo 8 caracteres, una mayúscula, un número y un símbolo"
    });
  }


    // 🔥 Validar si ya existe
    try {


  const hash = await bcrypt.hash(password, 10);

  const nuevoUsuario = new Usuario({
    email,
    password: hash,
    codigo_2fa: ""
  });

  await nuevoUsuario.save();

  res.json({ mensaje: "Usuario registrado" });
 } catch (error) {
    console.log(error); // 👈 AGREGA ESTO

// 🔥 ESTE ES EL CLAVE
    if (error.code === 11000) {
      return res.json({ mensaje: "El usuario ya existe" });
    }

        res.json({ mensaje: "Error en el servidor" });
 }

});

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const usuario = await Usuario.findOne({ email });

  if (!usuario) {
    return res.json({ mensaje: "Usuario no existe" });
  }

  const valid = await bcrypt.compare(password, usuario.password);

  if (!valid) {
    return res.json({ mensaje: "Contraseña incorrecta" });
  }

  res.json({ mensaje: "Login exitoso" });
});

// ruta para solicitar el codigo de recuperacion
app.post("/recuperar", async (req, res) => {
  try {
    const { email } = req.body;

    const usuario = await Usuario.findOne({ email });

    if (!usuario) {
      return res.json({ mensaje: "Usuario no existe" });
    }

    const token = Math.floor(100000 + Math.random() * 900000).toString();

    usuario.resetToken = token;
    await usuario.save();

    // 🔥 ENVIAR CORREO
    await transporter.sendMail({
      from: "Jona00043@gmail.com",
      to: email,
      subject: "Recuperación de contraseña",
      text: `Tu código de recuperación es: ${token}`
    });

    res.json({ mensaje: "Código enviado al correo" });

  } catch (error) {
    console.log(error);
    res.json({ mensaje: "Error al enviar correo" });
  }
});

// ruta para cambiar contraseña
app.post("/reset-password", async (req, res) => {
  const { email, token, nuevaPassword } = req.body;

  const usuario = await Usuario.findOne({ email });

  if (!usuario || usuario.resetToken !== token) {
    return res.json({ mensaje: "Token inválido" });
  }

  const hash = await bcrypt.hash(nuevaPassword, 10);

  usuario.password = hash;
  usuario.resetToken = "";
  await usuario.save();

  res.json({ mensaje: "Contraseña actualizada" });
});




// Servidor
app.listen(3000, () => {
  console.log("Servidor corriendo en puerto 3000");
});

// ruta para validar codigo

// funcion de modals
function abrirModal(id){
    document.getElementById(id).style.display = "block";
}

function cerrarModal(id){
    document.getElementById(id).style.display = "none";
}
