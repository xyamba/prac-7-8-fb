// index.js

const express = require('express');
const { nanoid } = require('nanoid');
const bcrypt = require('bcryptjs'); // ← здесь bcryptjs вместо bcrypt
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
const port = 3000;

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Практика 7 — Аутентификация + CRUD товаров',
            version: '1.0.0',
            description: 'Node.js сервер с регистрацией, логином и товарами (in-memory)',
        },
        servers: [{ url: `http://localhost:${port}` }],
    },
    apis: ['./index.js'], // этот файл сам себя документирует
};

let users = [];
let products = [];

// ────────────────────────────────────────────────
// Вспомогательные функции
// ────────────────────────────────────────────────

function findUserByEmail(email) {
    return users.find(u => u.email === email);
}

function findUserOr404(email, res) {
    const user = findUserByEmail(email);
    if (!user) {
        res.status(404).json({ error: "Пользователь не найден" });
        return null;
    }
    return user;
}

function findProductById(id) {
    return products.find(p => p.id === id);
}

function findProductOr404(id, res) {
    const product = findProductById(id);
    if (!product) {
        res.status(404).json({ error: "Товар не найден" });
        return null;
    }
    return product;
}

async function hashPassword(password) {
    const rounds = 10;
    return bcrypt.hash(password, rounds);
}

async function verifyPassword(password, hashedPassword) {
    return bcrypt.compare(password, hashedPassword);
}

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(express.json());

// Логирование запросов (для отладки)
app.use((req, res, next) => {
    res.on('finish', () => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${res.statusCode} ${req.path}`);
        if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
            console.log('Body:', req.body);
        }
    });
    next();
});

// ────────────────────────────────────────────────
// АУТЕНТИФИКАЦИЯ
// ────────────────────────────────────────────────

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Регистрация пользователя
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, first_name, last_name, password]
 *             properties:
 *               email:      { type: string, example: "user@example.com" }
 *               first_name: { type: string, example: "Иван" }
 *               last_name:  { type: string, example: "Петров" }
 *               password:   { type: string, example: "secret123" }
 *     responses:
 *       201:
 *         description: Пользователь создан
 *       400:
 *         description: Не переданы обязательные поля
 *       409:
 *         description: Пользователь с таким email уже существует
 */
app.post('/api/auth/register', async(req, res) => {
    const { email, first_name, last_name, password } = req.body;

    if (!email || !first_name || !last_name || !password) {
        return res.status(400).json({ error: "Обязательные поля: email, first_name, last_name, password" });
    }

    if (findUserByEmail(email)) {
        return res.status(409).json({ error: "Пользователь с таким email уже существует" });
    }

    const newUser = {
        id: nanoid(),
        email,
        first_name,
        last_name,
        hashedPassword: await hashPassword(password),
    };

    users.push(newUser);

    const { hashedPassword, ...userToReturn } = newUser;
    res.status(201).json(userToReturn);
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Вход в систему
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:    { type: string, example: "user@example.com" }
 *               password: { type: string, example: "secret123" }
 *     responses:
 *       200:
 *         description: Успешный вход
 *       400:
 *         description: Не переданы поля
 *       401:
 *         description: Неверный пароль
 *       404:
 *         description: Пользователь не найден
 */
app.post('/api/auth/login', async(req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Обязательные поля: email, password" });
    }

    const user = findUserOr404(email, res);
    if (!user) return;

    const isCorrect = await verifyPassword(password, user.hashedPassword);

    if (isCorrect) {
        res.json({ success: true, message: "Вход выполнен" });
    } else {
        res.status(401).json({ error: "Неверный пароль" });
    }
});

// ────────────────────────────────────────────────
// ТОВАРЫ (CRUD)
// ────────────────────────────────────────────────

/**
 * @swagger
 * /api/products:
 *   post:
 *     summary: Создать новый товар
 *     tags: [Products]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [title, category, description, price]
 *             properties:
 *               title:       { type: string }
 *               category:    { type: string }
 *               description: { type: string }
 *               price:       { type: number }
 *     responses:
 *       201: { description: Товар создан }
 *       400: { description: Не все поля }
 */
app.post('/api/products', (req, res) => {
    const { title, category, description, price } = req.body;

    if (!title || !category || !description || price == null) {
        return res.status(400).json({ error: "Обязательные поля: title, category, description, price" });
    }

    const newProduct = {
        id: nanoid(),
        title,
        category,
        description,
        price: Number(price),
    };

    products.push(newProduct);
    res.status(201).json(newProduct);
});

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Получить все товары
 *     tags: [Products]
 *     responses:
 *       200: { description: Список товаров }
 */
app.get('/api/products', (req, res) => {
    res.json(products);
});

/**
 * @swagger
 * /api/products/{id}:
 *   get:
 *     summary: Получить товар по ID
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Товар найден }
 *       404: { description: Товар не найден }
 */
app.get('/api/products/:id', (req, res) => {
    const product = findProductOr404(req.params.id, res);
    if (product) res.json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   put:
 *     summary: Обновить товар
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:       { type: string }
 *               category:    { type: string }
 *               description: { type: string }
 *               price:       { type: number }
 *     responses:
 *       200: { description: Товар обновлён }
 *       404: { description: Товар не найден }
 */
app.put('/api/products/:id', (req, res) => {
    const product = findProductOr404(req.params.id, res);
    if (!product) return;

    const { title, category, description, price } = req.body;

    if (title !== undefined) product.title = title;
    if (category !== undefined) product.category = category;
    if (description !== undefined) product.description = description;
    if (price !== undefined) product.price = Number(price);

    res.json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   delete:
 *     summary: Удалить товар
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       204: { description: Товар удалён }
 *       404: { description: Товар не найден }
 */
app.delete('/api/products/:id', (req, res) => {
    const index = products.findIndex(p => p.id === req.params.id);
    if (index === -1) {
        return res.status(404).json({ error: "Товар не найден" });
    }
    products.splice(index, 1);
    res.status(204).send();
});

// ────────────────────────────────────────────────

app.listen(port, () => {
    console.log(`Сервер запущен → http://localhost:${port}`);
    console.log(`Документация Swagger → http://localhost:${port}/api-docs`);
});