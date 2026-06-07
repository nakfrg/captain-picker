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

function generateSalt(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, "0")).join("");
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { currentPassword, newPassword } = await req.json();

    if (!currentPassword || !newPassword) {
      return new Response(JSON.stringify({ ok: false, error: "Missing fields" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 400,
      });
    }

    if (newPassword.length < 6) {
      return new Response(JSON.stringify({ ok: false, error: "Password must be at least 6 characters" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 400,
      });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // Fetch stored value
    const { data, error } = await supabase
      .from("guild_secrets")
      .select("value")
      .eq("key", "admin_password_hash")
      .single();

    if (error || !data) {
      return new Response(JSON.stringify({ ok: false, error: "Could not retrieve secret" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 500,
      });
    }

    // Verify current password — supports both plaintext: and salt:hash formats
    const stored: string = data.value;
    let valid = false;

    if (stored.startsWith("plaintext:")) {
      valid = currentPassword === stored.slice("plaintext:".length);
    } else {
      const [salt, storedHash] = stored.split(":");
      const attemptHash = await hashPassword(currentPassword, salt);
      valid = attemptHash === storedHash;
    }

    if (!valid) {
      return new Response(JSON.stringify({ ok: false, error: "Current password is incorrect" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 403,
      });
    }

    // Hash and store the new password with a fresh salt
    const newSalt = generateSalt();
    const newHash = await hashPassword(newPassword, newSalt);
    const newValue = `${newSalt}:${newHash}`;

    const { error: updateError } = await supabase
      .from("guild_secrets")
      .update({ value: newValue })
      .eq("key", "admin_password_hash");

    if (updateError) {
      return new Response(JSON.stringify({ ok: false, error: "Failed to update password" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 500,
      });
    }

    return new Response(JSON.stringify({ ok: true }), {
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
