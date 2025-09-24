export async function handleBallsUpload(request, env, pathname, corsHeaders) {
  const method = request.method;
  const headers = { "Content-Type": "application/json", ...corsHeaders };

  // Only handle POST /admin/balls g
  if (pathname === "/admin/balls" && method === "POST") {
    const contentType = request.headers.get("content-type") || "";

    if (!contentType.includes("multipart/form-data")) {
      return new Response(JSON.stringify({ message: "Invalid content type" }), {
        status: 400,
        headers,
      });
    }

    try {
      const formData = await request.formData();
      const password = formData.get("password");
      const file = formData.get("file");
      const filePath = formData.get("filePath");

      if (password !== "spacecat") {
        return new Response(
          JSON.stringify({ message: "Unauthorized: Invalid password" }),
          { status: 403, headers }
        );
      }

      if (!file || !filePath) {
        return new Response(
          JSON.stringify({ message: "Missing file or filePath" }),
          { status: 400, headers }
        );
      }

      // Stream upload into the FIXCORYSBALLS R2 bucket
      const stream = file.stream();
      await env.FIXCORYSBALLS.put(filePath, stream, {
        httpMetadata: { contentType: file.type },
      });

      return new Response(
        JSON.stringify({ message: `File uploaded to ${filePath}` }),
        { status: 200, headers }
      );
    } catch (err) {
      console.error("Balls upload error:", err);
      return new Response(JSON.stringify({ message: "Upload error" }), {
        status: 500,
        headers,
      });
    }
  }

  // If route does not match, return null so other handlers can process
  return null;
}
