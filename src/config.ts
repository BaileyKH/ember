process.loadEnvFile()

export type ApiConfig = {
  dbUrl: string;
  port: string;
  platform: string;
}

const dbURL = envOrThrow("dbURL")
const platform = envOrThrow("PLATFORM")
const port = envOrThrow("PORT")


export const cfg: ApiConfig = {
  dbUrl: dbURL,
  port: port,
  platform: platform,
}

function envOrThrow(key: string) {
  
  if (!process.env[key]) {
    throw new Error("No environment variable found")
  }

  return process.env[key]
}