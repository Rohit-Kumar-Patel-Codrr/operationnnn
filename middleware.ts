import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function middleware(request: NextRequest) {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return NextResponse.json(
      { error: "Supabase authentication is not configured." },
      { status: 500 }
    );
  }

  let response = NextResponse.next({ request });
  const supabase = createServerClient(supabaseUrl, supabaseAnonKey, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        cookiesToSet.forEach(({ name, value }) => {
          request.cookies.set(name, value);
        });
        response = NextResponse.next({ request });
        cookiesToSet.forEach(({ name, value, options }) => {
          response.cookies.set(name, value, options);
        });
      },
    },
  });

  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  const isUnauthenticated =
    error?.name === "AuthSessionMissingError" || error?.status === 401;
  if (error && !isUnauthenticated) {
    return NextResponse.json(
      { error: "Unable to verify the current session." },
      { status: 503 }
    );
  }

  const pathname = request.nextUrl.pathname;
  const isLoginPage = pathname === "/login";
  const isProtectedPage = pathname === "/";
  const isProtectedApi =
    pathname === "/api/devices" || pathname.startsWith("/api/devices/");
  const adminEmails = (process.env.DASHBOARD_ADMIN_EMAILS ?? "")
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
  const isAuthorized =
    !!user && !!user.email && adminEmails.includes(user.email.toLowerCase());

  if (!isAuthorized && isProtectedApi) {
    return NextResponse.json(
      { error: user ? "Administrator access required." : "Authentication required." },
      { status: user ? 403 : 401 }
    );
  }

  if (!isAuthorized && isProtectedPage) {
    const loginUrl = new URL("/login", request.url);
    if (user && adminEmails.length === 0) {
      loginUrl.searchParams.set("error", "admin_not_configured");
    } else if (user) {
      loginUrl.searchParams.set("error", "not_authorized");
    } else if (adminEmails.length === 0) {
      loginUrl.searchParams.set("error", "admin_not_configured");
    }
    const redirect = NextResponse.redirect(loginUrl);
    response.cookies.getAll().forEach((cookie) => {
      redirect.cookies.set(cookie);
    });
    return redirect;
  }

  if (isAuthorized && isLoginPage) {
    const redirect = NextResponse.redirect(new URL("/", request.url));
    response.cookies.getAll().forEach((cookie) => {
      redirect.cookies.set(cookie);
    });
    return redirect;
  }

  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api/telemetry).*)"],
};
