const cfg = require('../../pkg/config');
require('../../pkg/db');

const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('express-jwt');

const auth = require('./handlers/auth');

const api = express();

api.use(bodyParser.json());
api.use(jwt({
    secret: cfg.get('server').jwt_key,
    algorithms: ['HS256']
}).unless({
    path: [
        { url: '/api/v1/auth', methods: ['POST'] },
        { url: '/api/v1/auth/login', methods: ['POST'] },
        { url: '/api/v1/auth/forgot-password', methods: ['POST'] },
        { url: '/api/v1/auth/reset-password', methods: ['POST'] }
    ]
}));
api.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
        res.status(401).send('Bad JWT');
    }
});

api.post('/api/v1/auth', auth.create);
api.post('/api/v1/auth/login', auth.login);
api.get('/api/v1/auth/refresh-token', auth.refreshToken);
api.post('/api/v1/auth/forgot-password', auth.forgotPassword);
api.post('/api/v1/auth/reset-password', auth.resetPassword);
api.post('/api/v1/auth/change-password', auth.changePassword);

api.listen(cfg.get('server').port, err => {
    if (err) {
        return console.error('Could not start server:', err);
    }
    console.log('Server successfully started on port', cfg.get('server').port);
});