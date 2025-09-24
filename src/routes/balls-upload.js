export const ballsUpload = async ({ request, env }) => {
  const headers = { "Content-Type": "application/json" };

  try {
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.includes("multipart/form-data")) {
      return new Response(JSON.stringify({ message: "Invalid content type" }), {
        status: 400,
        headers,
      });
    }

    const formData = await request.formData();
    const password = formData.get("password");
    const file = formData.get("file");
    const filePath = formData.get("filePath");

    if (password !== "spacecat") {
      return new Response(JSON.stringify({ message: "Unauthorized: Invalid password" }), {
        status: 403,
        headers,
      });
    }

    if (!file || !filePath) {
      return new Response(JSON.stringify({ message: "Missing file or filePath" }), {
        status: 400,
        headers,
      });
    }

    // Stream the file into R2 (using your FIXCORYSBALLS binding)
    const stream = file.stream();
    await env.FIXCORYSBALLS.put(filePath, stream, {
      httpMetadata: { contentType: file.type },
    });

    return new Response(JSON.stringify({ message: `File uploaded to ${filePath}` }), {
      status: 200,
      headers,
    });
  } catch (err) {
    console.error("Upload error:", err);
    return new Response(JSON.stringify({ message: "Upload error" }), {
      status: 500,
      headers,
    });
  }
};
