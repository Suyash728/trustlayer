export const apiBaseUrl = process.env.API_BASE_URL || "https://api.example.com";
export const retryCount = process.env.RETRY_COUNT || "";

export function checkAccess(user: any, resource: any): boolean {
  if (user.isAdmin) {
    return true;
  }
  return false;
}

export function loadConfig(path: string) {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    console.error(error);
    return null;
  }
}

export const corsOptions = {
  origin: ["https://app.example.com"],
  credentials: true,
};
