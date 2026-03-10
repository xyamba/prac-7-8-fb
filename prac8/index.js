

const express = require('express');
const { nanoid } = require('nanoid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
const port = 3000;


const JWT_SECRET = "super-secret-key-2026-macbook";
const ACCESS_EXPIRES_IN = "1h";


const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Практика 8 — JWT Аутентификация',
            version: '1.0.0',
            description: 'API с регистрацией, входом и товарами (защищённые маршруты)',
        },
        servers: [{ url: `http://localhost:${port}` }],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
            },
            schemas: {
                UserRegister: {
                    type: 'object',
                    required: ['email', 'first_name', 'last_name', 'password'],
                    properties: {
                        email: {
                            type: 'string',
                            format: 'email',
                            example: 'user@example.com'
                        },
                        first_name: {
                            type: 'string',
                            example: 'Иван'
                        },
                        last_name: {
                            type: 'string',
                            example: 'Иванов'
                        },
                        password: {
                            type: 'string',
                            minLength: 6,
                            example: 'password123'
                        }
                    }
                },
                UserLogin: {
                    type: 'object',
                    required: ['email', 'password'],
                    properties: {
                        email: {
                            type: 'string',
                            format: 'email'
                        },
                        password: {
                            type: 'string'
                        }
                    }
                },
                Product: {
                    type: 'object',
                    properties: {
                        id: { type: 'string' },
                        title: { type: 'string' },
                        category: { type: 'string' },
                        description: { type: 'string' },
                        price: { type: 'number' }
                    }
                }
            }
        },
    },
    apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));


app.use(express.json());


app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
    next();
});


let users = [];
let products = [];


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
    return await bcrypt.hash(password, 10);
}

async function verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}


function authMiddleware(req, res, next) {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');

    if (scheme !== 'Bearer' || !token) {
        return res.status(401).json({
            error: 'Требуется авторизация. Используйте: Bearer <токен>'
        });
    }

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({
            error: 'Неверный или просроченный токен'
        });
    }
}

// === МАРШРУТЫ ===

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Зарегистрировать нового пользователя
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserRegister'
 *     responses:
 *       201:
 *         description: Пользователь создан
 */
app.post('/api/auth/register', async(req, res) => {
    const { email, first_name, last_name, password } = req.body;

    if (!email || !first_name || !last_name || !password) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }

    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.status(400).json({ error: 'Некорректный email' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
    }

    if (findUserByEmail(email)) {
        return res.status(409).json({ error: 'Пользователь с таким email уже существует' });
    }

    const hashedPassword = await hashPassword(password);

    const newUser = {
        id: nanoid(),
        email,
        first_name,
        last_name,
        hashedPassword,
    };

    users.push(newUser);

    const { hashedPassword: _, ...safeUser } = newUser;
    res.status(201).json(safeUser);
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Войти и получить JWT токен
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UserLogin'
 *     responses:
 *       200:
 *         description: Успешный вход
 */
app.post('/api/auth/login', async(req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email и пароль обязательны' });
    }

    const user = findUserOr404(email, res);
    if (!user) return;

    const isValid = await verifyPassword(password, user.hashedPassword);
    if (!isValid) {
        return res.status(401).json({ error: 'Неверный пароль' });
    }

    const accessToken = jwt.sign({ sub: user.id, email: user.email },
        JWT_SECRET, { expiresIn: ACCESS_EXPIRES_IN }
    );

    res.json({ accessToken });
});

// === ТОВАРЫ ===

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Получить список всех товаров
 *     tags: [Products]
 *     responses:
 *       200:
 *         description: Список товаров
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Product'
 */
app.get('/api/products', (req, res) => {
    res.json(products);
});

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
 *             $ref: '#/components/schemas/Product'
 *     responses:
 *       201:
 *         description: Товар создан
 */
app.post('/api/products', (req, res) => {
    const { title, category, description, price } = req.body;

    if (!title || !category || !description || price == null) {
        return res.status(400).json({
            error: 'Обязательные поля: title, category, description, price'
        });
    }

    if (typeof price !== 'number' || price < 0) {
        return res.status(400).json({ error: 'Цена должна быть числом >= 0' });
    }

    const newProduct = {
        id: nanoid(),
        title,
        category,
        description,
        price,
    };

    products.push(newProduct);
    res.status(201).json(newProduct);
});

/**
 * @swagger
 * /api/products/{id}:
 *   get:
 *     summary: Получить товар по ID
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: ID товара
 *     responses:
 *       200:
 *         description: Товар найден
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Product'
 *       404:
 *         description: Товар не найден
 */
app.get('/api/products/:id', authMiddleware, (req, res) => {
    const product = findProductOr404(req.params.id, res);
    if (product) res.json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   put:
 *     summary: Обновить товар
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Product'
 *     responses:
 *       200:
 *         description: Товар обновлён
 */
app.put('/api/products/:id', authMiddleware, (req, res) => {
    const product = findProductOr404(req.params.id, res);
    if (!product) return;

    const { title, category, description, price } = req.body;

    if (title) product.title = title;
    if (category) product.category = category;
    if (description) product.description = description;
    if (price !== undefined) {
        if (typeof price !== 'number' || price < 0) {
            return res.status(400).json({ error: 'Цена должна быть числом >= 0' });
        }
        product.price = price;
    }

    res.json(product);
});

/**
 * @swagger
 * /api/products/{id}:
 *   delete:
 *     summary: Удалить товар
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Товар успешно удалён
 */
app.delete('/api/products/:id', authMiddleware, (req, res) => {
    const index = products.findIndex(p => p.id === req.params.id);
    if (index === -1) {
        return res.status(404).json({ error: 'Товар не найден' });
    }

    products.splice(index, 1);
    res.status(204).send();
});
app.listen(port, () => {
    console.log(`🚀 Сервер запущен: http://localhost:${port}`);
    console.log(`📘 Swagger: http://localhost:${port}/api-docs`);
});
