import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

async function hashPassword(password: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { password } = await req.json();

    if (!password) {
      return new Response(JSON.stringify({ ok: false, error: "No password provided" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 400,
      });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data, error } = await supabase
      .from("guild_secrets")
      .select("value")
      .eq("key", "admin_password_hash")
      .single();

    if (error || !data) {
      return new Response(JSON.stringify({ ok: false, error: "Secret not found" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 500,
      });
    }

    const stored: string = data.value;
    let valid = false;

    if (stored.startsWith("plaintext:")) {
      // Bootstrap mode — compare directly
      valid = password === stored.slice("plaintext:".length);
    } else {
      // Normal mode — salt:hash format
      const [salt, storedHash] = stored.split(":");
      const attemptHash = await hashPassword(password, salt);
      valid = attemptHash === storedHash;
    }

    return new Response(JSON.stringify({ ok: valid }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: String(err) }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 500,
    });
  }
});
