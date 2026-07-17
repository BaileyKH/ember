process.loadEnvFile()

export type ApiConfig = {
  dbUrl: string;
  port: string;
  platform: string;
  jwtSecret: string;
  rateLimitSecret: string;
  frontendOrigin?: string;
  trustProxy?: string | number;
  passwordResetUrl?: string;
  passwordResetWebhookUrl?: string;
  passwordResetWebhookSecret?: string;
}

const dbURL = envOrThrow("dbURL")
const platform = envOrThrow("PLATFORM")
const port = envOrThrow("PORT")
const jwtSecret = secretOrThrow("SECRET")
const rateLimitSecret = secretOrThrow("RATE_LIMIT_SECRET")
const frontendOrigin = originOrUndefined("FRONTEND_ORIGIN")
const trustProxy = trustProxyOrUndefined("TRUST_PROXY")
const passwordResetUrl = urlOrUndefined("PASSWORD_RESET_URL")
const passwordResetWebhookUrl = urlOrUndefined("PASSWORD_RESET_WEBHOOK_URL")
const passwordResetWebhookSecret = optionalSecret("PASSWORD_RESET_WEBHOOK_SECRET")

if (platform !== "dev") {
  for (const [key, value] of [
    ["PASSWORD_RESET_URL", passwordResetUrl],
    ["PASSWORD_RESET_WEBHOOK_URL", passwordResetWebhookUrl],
  ] as const) {
    if (value && new URL(value).protocol !== "https:") {
      throw new Error(`${key} must use HTTPS outside development`)
    }
  }
}

if (Boolean(passwordResetWebhookUrl) !== Boolean(passwordResetWebhookSecret)) {
  throw new Error(
    "PASSWORD_RESET_WEBHOOK_URL and PASSWORD_RESET_WEBHOOK_SECRET must be configured together",
  )
}


export const cfg: ApiConfig = {
  dbUrl: dbURL,
  port: port,
  platform: platform,
  jwtSecret: jwtSecret,
  rateLimitSecret: rateLimitSecret,
  frontendOrigin: frontendOrigin,
  trustProxy: trustProxy,
  passwordResetUrl,
  passwordResetWebhookUrl,
  passwordResetWebhookSecret,
}

function envOrThrow(key: string) {
  
  if (!process.env[key]) {
    throw new Error(`Missing required environment variable: ${key}`)
  }

  return process.env[key]
}

function originOrUndefined(key: string) {
  const value = process.env[key]?.trim()
  if (!value) return undefined

  const url = new URL(value)
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error(`${key} must contain only an origin`)
  }

  return url.origin
}

function urlOrUndefined(key: string) {
  const value = process.env[key]?.trim()
  if (!value) return undefined

  return new URL(value).toString()
}

function optionalSecret(key: string) {
  const value = process.env[key]?.trim()
  if (!value) return undefined
  if (Buffer.byteLength(value, "utf8") < 32) {
    throw new Error(`${key} must be at least 32 bytes`)
  }

  return value
}

function secretOrThrow(key: string) {
  const value = envOrThrow(key)
  if (Buffer.byteLength(value, "utf8") < 32) {
    throw new Error(`${key} must be at least 32 bytes`)
  }

  return value
}

function trustProxyOrUndefined(key: string): string | number | undefined {
  const value = process.env[key]?.trim()
  if (!value) return undefined

  if (/^\d+$/.test(value)) {
    return Number(value)
  }

  return value
}
