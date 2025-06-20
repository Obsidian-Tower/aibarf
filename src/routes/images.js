export async function handleImages(request, env, pathname, corsHeaders) {
  const method = request.method;

  // /images/sets/{setId}/{fileName}
  if (pathname.startsWith('/images/sets/') && method === 'GET') {
    const [, , , setId, fileName] = pathname.split('/');
    const key = `sets/${setId}/${fileName}`;
    const obj = await env.USER_IMAGES.get(key);

    if (!obj || !obj.body) {
      return new Response('Not found', { status: 404 });
    }

    return new Response(obj.body, {
      status: 200,
      headers: {
        'Content-Type': obj.httpMetadata.contentType,
        'Cache-Control': 'public, max-age=31536000',
      },
    });
  }

  // /images/profile-images/{fileName}
  if (pathname.startsWith('/images/profile-images/') && method === 'GET') {
    const [, , , fileName] = pathname.split('/');
    const key = `profile-images/${fileName}`;
    const obj = await env.USER_IMAGES.get(key);

    if (!obj || !obj.body) {
      return new Response('Not found', { status: 404 });
    }

    return new Response(obj.body, {
      status: 200,
      headers: {
        'Content-Type': obj.httpMetadata.contentType,
        'Cache-Control': 'public, max-age=31536000',
      },
    });
  }

  // /images/assets/{...path}
  if (pathname.startsWith('/images/assets/') && method === 'GET') {
    const assetPath = pathname.slice('/images/assets/'.length); // gets nested path
    const key = `assets/${assetPath}`;
    const obj = await env.USER_IMAGES.get(key);

    if (!obj || !obj.body) {
      return new Response('Not found', { status: 404 });
    }

    return new Response(obj.body, {
      status: 200,
      headers: {
        'Content-Type': obj.httpMetadata.contentType,
        'Cache-Control': 'public, max-age=31536000',
      },
    });
  }

  // No image route matched
  return null;
}
