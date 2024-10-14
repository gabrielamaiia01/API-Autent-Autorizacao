require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./models/User')

app.get('/', (req,res) => {
    res.status(200).json({ msg: 'bem vindo a nosso api!'})
})

// Rota protegida para buscar usuário por ID
app.get("/user/:id",checkToken, async (req, res) => {

   const id = req.params.id // Obtém o ID do usuário a partir dos parâmetros da URL

   const user = await User.findById(id, '-password') // Busca o usuário excluindo o campo de senha

   if (!user){
    return res.status(404).json({msg: 'Usuário não encontrado! '})
   }
 
   res.status(200).json({user})
})

// Middleware para verificar o token JWT
function checkToken(req, res, next){

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split("")[1] // Extrai o token (corrigido: estava faltando o espaço no split)

    if(!token){
        return res.status(401).json({msg: 'acesso negado!'})
    }

    try{ 

        const secret = process.env.SECRET

        jwt.verity(token, secret) // Verifica se o token é válido

        next()

    } catch(error){
        res.status(400).json({msg: 'token inválido!'})
    }
}

app.post("/auth/register", async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;
  
    // validations
    if (!name) {
      return res.status(422).json({ msg: "O nome é obrigatório!" });
    }
  
    if (!email) {
      return res.status(422).json({ msg: "O email é obrigatório!" });
    }
  
    if (!password) {
      return res.status(422).json({ msg: "A senha é obrigatória!" });
    }
  
    if (password != confirmpassword) {
      return res
        .status(422)
        .json({ msg: "A senha e a confirmação precisam ser iguais!" });
    }
  
    // check if user exists
    const userExists = await User.findOne({ email: email });
  
    if (userExists) {
      return res.status(422).json({ msg: "Por favor, utilize outro e-mail!" });
    }
  
    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);
  
    // create user
    const user = new User({
      name,
      email,
      password: passwordHash,
    });
  
    try {
      await user.save();
  
      res.status(201).json({ msg: "Usuário criado com sucesso!" });
    } catch (error) {
      res.status(500).json({ msg: error });
    }
  });

  //login 
  app.post("/auth/login", async (req, res) => {
    
    const {email, password} = req.body

    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório!" });
      }
    
      if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória!" });
      }


    const user = await User.findOne({ email: email });
  
    if (!user) {
     return res.status(422).json({ msg: "usuário não encontrado!" });
    }
    
    const checkPassword = await bcrypt.compare(password, user.password)
    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida" });
      }

    try{
      const secret = process.env.secret

      const token = jwt.sign(
        {
        id: user._id,
        }, 
        secret, 
    )

    res.status(200).json({msg: "autenticação realizada com sucesso!", token })

    } catch (err){
      console.log(error)

      res.status(500).json({
        msg: 'Aconteceu um erro no servidor, tente novamente!',
      })
    }

  })

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.xwohk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
 ).then(() => {
 app.listen(3000)
 console.log("Conectou ao banco!")
}).catch((err) => console.log(err))

//app.listen(3000)