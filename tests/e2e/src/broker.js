// Starts a broker with a minimal config.

const crypto = require("crypto");
const path = require("path");
const readline = require("readline");
const { spawn } = require("child_process");

const {
  RUST_LOG,
  TEST_STORE,
  TEST_KEY_MANAGER,
  TEST_MAILER
} = require("./env");

const ROOT = path.resolve(__dirname, "../../../");
const BIN = path.resolve(ROOT, "target/debug/portier-broker");

module.exports = ({ mailbox }) => {
  const env = {
    RUST_LOG,
    RUST_BACKTRACE: "1",
    BROKER_LISTEN_PORT: "44133",
    BROKER_PUBLIC_URL: "http://localhost:44133",
    BROKER_FROM_ADDRESS: "portier@example.com",
    BROKER_LIMIT_PER_EMAIL: "10000/min"
  };

  switch (TEST_STORE) {
    case "memory":
      env.BROKER_MEMORY_STORAGE = "true";
      break;
    case "redis":
      env.BROKER_REDIS_URL = "redis://localhost/0";
      break;
    case "sqlite":
      const id = String(Math.random()).slice(2);
      env.BROKER_SQLITE_DB = `/tmp/portier-broker-test-${id}.sqlite3`;
      break;
    default:
      throw Error(`Invalid TEST_STORE: ${TEST_STORE}`);
  }

  switch (TEST_KEY_MANAGER) {
    case "rotating":
      break;
    case "manual":
      const { privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048
      });
      env.BROKER_KEYTEXT = privateKey.export({
        type: "pkcs8",
        format: "pem"
      });
      break;
    default:
      throw Error(`Invalid TEST_KEY_MANAGER: ${TEST_KEY_MANAGER}`);
  }

  switch (TEST_MAILER) {
    case "smtp":
      env.BROKER_SMTP_SERVER = "127.0.0.1:44125";
      break;
    case "sendmail":
      env.BROKER_SENDMAIL_COMMAND = `${__dirname}/sendmail.sh`;
      break;
    default:
      throw Error(`Invalid TEST_MAILER: ${TEST_MAILER}`);
  }

  const subprocess = spawn(BIN, {
    stdio: ["ignore", "inherit", "pipe"],
    cwd: ROOT,
    env
  });

  // Parse `sendmail.sh` output appearing on broker stderr.
  let inMail = false;
  let mailBuffer = "";
  readline
    .createInterface({
      input: subprocess.stderr,
      crlfDelay: Infinity
    })
    .on("line", line => {
      if (line === "-----BEGIN SENDMAIL INPUT-----") {
        inMail = true;
        mailBuffer = "";
      } else if (line === "-----END SENDMAIL INPUT-----") {
        const mail = mailBuffer;
        inMail = false;
        mailBuffer = "";
        if (mail) {
          mailbox.pushRawMail(mail);
        }
      } else if (inMail) {
        mailBuffer += `${line}\n`;
      } else {
        process.stderr.write(`${line}\n`);
      }
    });

  return {
    destroy() {
      subprocess.kill();
    }
  };
};
