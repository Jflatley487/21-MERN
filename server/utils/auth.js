const jwt = require('jsonwebtoken');
const { AuthenticationError } = require('apollo-server-express');
const { secret, expiration } = require('../config/auth'); 

const authMiddleware = (context) => {
  const { req } = context;
  let token = req.headers.authorization;

  if (req.headers.authorization) {
    token = token.split(' ').pop().trim();
  }

  if (!token) {
    throw new AuthenticationError('You have no token!');
  }

  try {
    const { data } = jwt.verify(token, secret, { maxAge: expiration });
    context.user = data;
  } catch (err) {
    console.log('Invalid token');
    throw new AuthenticationError('Invalid token!');
  }
};

module.exports = authMiddleware;

