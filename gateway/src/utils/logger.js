const winston = require('winston');
const path = require('path');
const fs = require('fs');

const logDir = path.resolve(process.env.LOG_DIR || path.join(__dirname, '..', '..', 'logs'));
try {
  fs.mkdirSync(logDir, { recursive: true });
} catch (err) {
  // Directory creation failed — fall back to stdout-only logging below
  console.error(`[logger] could not create ${logDir}: ${err.message}`);
}

const transports = [
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.colorize(),
      winston.format.printf(({ timestamp, level, message }) =>
        `[${timestamp}] ${level}: ${message}`)
    ),
  }),
];

if (fs.existsSync(logDir) && fs.statSync(logDir).isDirectory()) {
  transports.push(new winston.transports.File({ filename: path.join(logDir, 'error.log'), level: 'error' }));
  transports.push(new winston.transports.File({ filename: path.join(logDir, 'combined.log') }));
}

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) => {
      return `[${timestamp}] ${level}: ${message}`;
    })
  ),
  transports,
  exitOnError: false,
});

module.exports = logger;
