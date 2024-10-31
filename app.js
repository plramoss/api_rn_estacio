const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const saltRounds = 10;

dotenv.config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

pool.connect(undefined).then(r => console.log('Connected: ' + r)).catch(e => console.log('Error: ' + e));

const app = express();
const port = 3000;

const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'API Projeto de extensão - Estácio',
      description: 'Library API Information',
    },
    servers: [{ url: 'http://localhost:3000' }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        }
      }
    },
  },
  apis: ['./app.js']
}

// Gera documentação do swagger com base nas options
const swaggerDocs = swaggerJsdoc(swaggerOptions);

// Endpoint das docs do swagger
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Middleware para verificar token
app.use(express.json());

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}/api/docs`);
});

module.exports = app;

/**
 * @swagger
 * /api/auth:
 *   post:
 *     description: Obter um token de acesso
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Resposta bem-sucedida
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 */
app.post('/api/auth', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Email e/ou senha inválidos' });
    }
    
    const token = jwt.sign({ user }, process.env.TOKEN_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ message: 'Erro ao autenticar usuário' });
  }
})

/**
 * @swagger
 * /api/usuario:
 *   post:
 *     description: Criar um novo usuário
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nome:
 *                 type: string
 *               sobrenome:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Resposta bem-sucedida
 */
app.post('/api/usuario', async (req, res) => {
  const { nome, sobrenome, email, password } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await pool.query('INSERT INTO usuarios (nome, sobrenome, email, password) VALUES ($1, $2, $3, $4)', [nome, sobrenome, email, hashedPassword]);
    res.json({ message: 'Usuário cadastrado com sucesso' });
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).json({ message: 'Erro ao cadastrar usuário' });
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

/**
 * @swagger
 * /api/alimentos:
 *   get:
 *     security:
 *       - bearerAuth: []
 *     description: Utilize para buscar dados alimentos se baseado no nome
 *     parameters:
 *       - in: query
 *         name: nome
 *         schema:
 *           type: string
 *         description: Nome do alimento
 *     responses:
 *       '200':
 *         description: Resposta bem-sucedida
 *         content:
 *           application/json:
 *             schema:
 *               properties:
 *                 id:
 *                   type: integer
 *                 nome:
 *                   type: string
 *                 calorias:
 *                   type: integer
 *                 proteina:
 *                   type: integer
 *                 carboidrato:
 *                   type: integer
 *                 gordura:
 *                   type: integer
 *       '401':
 *         description: Não autorizado
 *       '403':
 *         description: Proibido
 */
app.get('/api/alimentos', authenticateToken, async (req, res) => {
  const { nome } = req.query;
  
  try {
    let query = 'SELECT * FROM alimentos';
    const params = [];
    
    if (nome) {
      query += ' WHERE nome = $1';
      params.push(`%${nome}%`);
    }
    
    const response = await pool.query(query, params);
    res.json(response.rows);
  } catch (e) {
    console.log(e);
    res.status(500).json({ message: 'Erro ao buscar alimentos' });
  }
});