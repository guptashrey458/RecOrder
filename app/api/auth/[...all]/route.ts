import aj, {
  ArcjetDecision,
  shield,
  slidingWindow,
  validateEmail,
} from "@/lib/arcjet";
import ip from "@arcjet/ip";
import { auth } from "@/lib/auth";
import { toNextJsHandler } from "better-auth/next-js";
import { NextRequest } from "next/server";

// Set maximum duration for this route (Next.js/Vercel)
export const maxDuration = 60; // 60 seconds ⚡

// Configure Arcjet rules outside handler for better performance
const emailValidation = aj.withRule(
  validateEmail({
    mode: "LIVE",
    block: ["DISPOSABLE", "INVALID", "NO_MX_RECORDS"],
  })
);

const rateLimit = aj.withRule(
  slidingWindow({
    mode: "LIVE",
    interval: "2m",
    max: 2,
    characteristics: ["fingerprint"],
  })
);

const shieldValidation = aj.withRule(
  shield({
    mode: "LIVE",
  })
);

// Cache IP lookups to reduce latency
const getUserId = async (req: NextRequest) => {
  const session = await auth.api.getSession({
    headers: req.headers,
  });
  return session?.user?.id || ip(req) || "127.0.0.1";
};

const protectedAuth = async (req: NextRequest): Promise<ArcjetDecision> => {
  try {
    const userId = await getUserId(req);
    const path = req.nextUrl.pathname;

    if (path.startsWith("/api/auth/sign-in")) {
      const body = await req.clone().json();
      if (typeof body.email === "string") {
        return emailValidation.protect(req, { email: body.email });
      }
    }

    if (!path.startsWith("/api/auth/sign-out")) {
      return rateLimit.protect(req, { fingerprint: userId });
    }

    return shieldValidation.protect(req);
  } catch (error) {
    console.error("Auth protection failed:", error);
    throw error;
  }
};

const authHandlers = toNextJsHandler(auth.handler);

export const { GET } = authHandlers;

export const POST = async (req: NextRequest) => {
  try {
    const decision = await protectedAuth(req);
    
    if (decision.isDenied()) {
      return new Response(decision.reason.message, {
        status: decision.reason.statusCode,
      });
    }

    return authHandlers.POST(req);
  } catch (error) {
    console.error("API route error:", error);
    return new Response("Internal Server Error", { status: 500 });
  }
};
