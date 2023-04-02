const express = require("express");
const app = express();
const fs = require('fs');
const winston = require('winston');
const passport = require('passport');
const passportJWT = require("passport-jwt");
const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;
const jwt = require('jsonwebtoken');
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'calculate-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

const secretKey = 'your-secret-key';

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secretKey
};

const jwtStrategy = new JwtStrategy(jwtOptions, (payload, done) => {
  done(null, true);
});

passport.use(jwtStrategy);

const authenticateJWT = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user, info) => {
    if (err) {
      logger.error(err.message);
      return res.status(401).json({ statuscode: 401, msg: 'Unauthorized' });
    }
    if (!user) {
      logger.error(info.message);
      return res.status(401).json({ statuscode: 401, msg: 'Unauthorized' });
    }
    req.user = user;
    next();
  })(req, res, next);
};
const authorizeUser = (req, res, next) => {
  next();
};

const add = (n1, n2) => {
  return n1 + n2;
};

const subtract = (n1, n2) => {
  return n1 - n2;
};

const multiply = (n1, n2) => {
  return n1 * n2;
};

const divide = (n1, n2) => {
  if (n2 === 0) {
    logger.error('Cannot divide by zero');
    throw new Error('Cannot divide by zero');
  }
  return n1 / n2;
};

app.get("/add", authenticateJWT, authorizeUser, (req, res) => {
    try {
        const n1 = parseFloat(req.query.n1);
        const n2 = parseFloat(req.query.n2);
        if (isNaN(n1)) {
            logger.error("n1 is incorrectly defined");
            throw new Error("n1 incorrectly defined");
        }
        if (isNaN(n2)) {
            logger.error("n2 is incorrectly defined");
            throw new Error("n2 incorrectly defined");
        }
        logger.info('Parameters ' + n1 + ' and ' + n2 + ' received for addition');
        const result = add(n1, n2);
        res.status(200).json({ statuscode: 200, data: result });
    }
    catch (error) {
          logger.error(error.toString());
          res.status(500).json({ statuscode: 500, msg: error.toString() });
        }
   
});

app.get("/subtract", authenticateJWT, authorizeUser, (req, res) => {
    try {
        const n1 = parseFloat(req.query.n1);
        const n2 = parseFloat(req.query.n2);

        if (isNaN(n1)) {
            logger.error("n1 is incorrectly defined");
            throw new Error("n1 incorrectly defined");
        }

        if (isNaN(n2)) {
            logger.error("n2 is incorrectly defined");
            throw new Error("n2 incorrectly defined");
        }

        logger.info(
            "Parameters " + n1 + " and " + n2 + " received for subtraction"
        );
        const result = subtract(n1, n2);
        res.status(200).json({ statuscode: 200, data: result });
    } catch (error) {
        logger.error(error.toString());
        res.status(500).json({ statuscode: 500, msg: error.toString() });
    }
});
app.get("/multiply", authenticateJWT, authorizeUser, (req, res) => {
    try {
        const n1 = parseFloat(req.query.n1);
        const n2 = parseFloat(req.query.n2);

        if (isNaN(n1)) {
            logger.error("n1 is incorrectly defined");
            throw new Error("n1 incorrectly defined");
        }

        if (isNaN(n2)) {
            logger.error("n2 is incorrectly defined");
            throw new Error("n2 incorrectly defined");
        }

        logger.info(
            "Parameters " + n1 + " and " + n2 + " received for multiplication"
        );
        const result = multiply(n1, n2);
        res.status(200).json({ statuscode: 200, data: result });
    } catch (error) {
        logger.error(error.toString());
        res.status(500).json({ statuscode: 500, msg: error.toString() });
    }
});
app.get("/divide", authenticateJWT, authorizeUser, (req, res) => {
    try {
        const n1 = parseFloat(req.query.n1);
        const n2 = parseFloat(req.query.n2);

        if (isNaN(n1)) {
            logger.error("n1 is incorrectly defined");
            throw new Error("n1 incorrectly defined");
        }

        if (isNaN(n2)) {
            logger.error("n2 is incorrectly defined");
            throw new Error("n2 incorrectly defined");
        }

        logger.info(
            "Parameters " + n1 + " and " + n2 + " received for division"
        );
        const result = divide(n1, n2);
        res.status(200).json({ statuscode: 200, data: result });
    } catch (error) {
        logger.error(error.toString());
        res.status(500).json({ statuscode: 500, msg: error.toString() });
    }
});
const port = 3040;
app.listen(port, () => {
    console.log("hello i'm listening to port " + port);
})